"""Tests for session checkpoint HTTP export/import when swapping SQLite files.

A checkpoint exported from one database lets an existing collection session
continue in another database under its original ``session_id``:

* ``GET /sessions/{id}/checkpoint`` returns one committed snapshot: exact
  protocol version and definition digest, received offset, raw pending tail,
  cumulative frame count, last fragment digest and original response, and the
  sequence-audit progress when enabled;
* ``POST /sessions/import`` only accepts a checkpoint whose exact protocol
  version is registered in the target database with the identical definition
  digest *and* whose audit modulus is that protocol's effective sequence-field
  bit width, when no session with the same id exists there yet, and when the
  envelope is internally self-consistent (tail start/offset and the stored
  response agree); failure never touches existing target state;
* after import, frames split across the migration boundary decode once, the
  sequence audit keeps its baseline, resending the last fragment replays the
  original response without double counting, and audit values past SQLite's
  signed 64-bit INTEGER range stay exact.
"""
from __future__ import annotations

import copy
import sqlite3
import threading

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import b64, build_logical, standard_protocol
from tests.test_sequence_audit_wide import (
    INT64_MAX,
    frame64,
    u64_protocol,
)

SYNC = b"\xaa\x55"


def make_client(db_path, *, max_decode_bytes=1 << 20):
    return TestClient(
        create_app(Settings(db_path=db_path, max_decode_bytes=max_decode_bytes))
    )


def register_standard(client, **overrides):
    r = client.post("/protocols", json=standard_protocol(**overrides))
    assert r.status_code == 201, r.text


def register_u64(client, **overrides):
    r = client.post("/protocols", json=u64_protocol(**overrides))
    assert r.status_code == 201, r.text


def make_session(client, payload):
    r = client.post("/sessions", json=payload)
    assert r.status_code == 201, r.text
    return r.json()["session_id"]


def append(client, sid, offset, chunk):
    return client.post(
        "/sessions/append",
        json={"session_id": sid, "expected_offset": offset, "chunk_b64": b64(chunk)},
    )


def export_checkpoint(client, sid):
    r = client.get(f"/sessions/{sid}/checkpoint")
    assert r.status_code == 200, r.text
    return r.json()


def import_checkpoint(client, checkpoint):
    return client.post("/sessions/import", json=checkpoint)


def _seed_split_session(client, *, audit=False):
    """A session whose last fragment ends in a 1-byte pending tail."""
    sid = make_session(
        client,
        {"protocol_id": "sensor-line", "version": 1, "sequence_audit": audit},
    )
    chunk = b"\x12" + SYNC + build_logical(1, 3, 2345) + b"\xaa"
    d = append(client, sid, 0, chunk).json()
    assert d["next_offset"] == len(chunk)
    return sid, chunk


# --------------------------------------------------------------- export -----


def test_export_unknown_session_404(client):
    r = client.get("/sessions/00000000000000000000000000000000/checkpoint")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "SESSION_NOT_FOUND"


def test_export_carries_every_committed_state_field(client):
    register_standard(client)
    sid = make_session(
        client, {"protocol_id": "sensor-line", "version": 1, "sequence_audit": True}
    )
    chunk = b"\x12" + SYNC + build_logical(1, 3, 0) + b"\xaa"
    d = append(client, sid, 0, chunk).json()

    cp = export_checkpoint(client, sid)
    assert cp["format_version"] == 1
    assert cp["exported_at"]
    assert cp["session_id"] == sid
    assert cp["protocol_id"] == "sensor-line"
    assert cp["version"] == 1
    assert len(cp["definition_sha256"]) == 64
    assert cp["received_offset"] == len(chunk)
    assert cp["tail_b64"] == b64(b"\xaa")
    assert cp["frames_total"] == 1
    assert cp["last_chunk_offset"] == 0
    assert len(cp["last_chunk_sha256"]) == 64
    assert cp["audit_enabled"] is True
    audit = cp["sequence_audit"]
    assert audit["bit_width"] == 8
    assert audit["last_sequence"] == 1
    assert audit["duplicates"] == 0
    # The original response is carried verbatim (replayed flag stays false).
    resp = cp["last_response"]
    assert resp["replayed"] is False
    assert resp["next_offset"] == len(chunk)
    assert resp["frames"] == d["frames"]
    assert resp["tail"] == d["tail"]
    assert resp["sequence_audit"]["last_sequence"] == 1


def test_export_of_never_appended_session_is_pristine(client):
    register_standard(client)
    sid = make_session(client, {"protocol_id": "sensor-line", "version": 1})
    cp = export_checkpoint(client, sid)
    assert cp["received_offset"] == 0
    assert cp["tail_b64"] == ""
    assert cp["frames_total"] == 0
    assert cp["last_chunk_offset"] is None
    assert cp["last_chunk_sha256"] is None
    assert cp["last_response"] is None
    assert cp["audit_enabled"] is False
    assert cp["sequence_audit"] is None


def test_export_matches_the_protocol_definition_digest(client):
    register_standard(client)
    sid = make_session(client, {"protocol_id": "sensor-line", "version": 1})
    cp = export_checkpoint(client, sid)
    digest = client.get("/protocols").json()["protocols"][0]["definition_sha256"]
    assert cp["definition_sha256"] == digest


# ----------------------------------------------------- import happy path ----


def test_import_then_replay_and_continue_across_databases(db_path, tmp_path):
    src = make_client(db_path)
    register_standard(src)
    sid, first_chunk = _seed_split_session(src)
    cp = export_checkpoint(src, sid)

    dst_path = str(tmp_path / "target.db")
    dst = make_client(dst_path)
    # Protocol missing in the target: import refuses.
    r = import_checkpoint(dst, cp)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "SESSION_IMPORT_INVALID"
    assert err["details"]["reason"] == "protocol_mismatch"
    assert dst.get(f"/sessions/{sid}").status_code == 404

    register_standard(dst)
    r = import_checkpoint(dst, cp)
    assert r.status_code == 201, r.text
    progress = r.json()
    assert progress["session_id"] == sid
    assert progress["received_offset"] == len(first_chunk)
    assert progress["frames_total"] == 1
    assert progress["tail"]["payload_b64"] == b64(b"\xaa")
    assert progress["last_chunk_offset"] == 0

    # Resending the most recent fragment returns the original response,
    # marked replayed, without counting its frame again.
    replay = append(dst, sid, 0, first_chunk).json()
    assert replay["replayed"] is True
    assert replay["frames_total"] == 1
    assert replay["frames"][0]["sequence"] == 1
    assert replay["frames"][0]["start"] == 1

    # Cross-shard decode continues: the dangling 0xAA + next bytes complete
    # frame 2 at the original cumulative position.
    rest = b"\x55" + build_logical(2, 3, 100)
    cont = append(dst, sid, len(first_chunk), rest).json()
    assert cont["replayed"] is False
    assert len(cont["frames"]) == 1
    assert cont["frames"][0]["sequence"] == 2
    assert cont["frames"][0]["start"] == len(first_chunk) - 1
    assert cont["frames_total"] == 2


def test_imported_pristine_session_starts_fresh_at_offset_zero(db_path, tmp_path):
    src = make_client(db_path)
    register_standard(src)
    sid = make_session(src, {"protocol_id": "sensor-line", "version": 1})
    cp = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst)
    r = import_checkpoint(dst, cp)
    assert r.status_code == 201
    assert r.json()["received_offset"] == 0
    chunk = SYNC + build_logical(7, 1, 0)
    d = append(dst, sid, 0, chunk).json()
    assert d["frames"][0]["sequence"] == 7
    assert d["frames_total"] == 1


def test_imported_audit_session_keeps_baseline_and_accumulates(db_path, tmp_path):
    src = make_client(db_path)
    register_standard(src)
    sid = make_session(
        src, {"protocol_id": "sensor-line", "version": 1, "sequence_audit": True}
    )
    # Sequences 1, 2, 4 -> one suspected gap (missing 3).
    chunk = (
        SYNC + build_logical(1, 3, 0)
        + SYNC + build_logical(2, 3, 0)
        + SYNC + build_logical(4, 3, 0)
    )
    d = append(src, sid, 0, chunk).json()
    assert d["sequence_audit"]["suspected_gaps"] == 1
    cp = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst)
    assert import_checkpoint(dst, cp).status_code == 201
    audit = dst.get(f"/sessions/{sid}").json()["sequence_audit"]
    assert audit["last_sequence"] == 4
    assert audit["suspected_gaps"] == 1
    assert audit["missing_total"] == 1

    # Frame 5 continues from the imported baseline (no new anomaly).
    cont = append(dst, sid, len(chunk), SYNC + build_logical(5, 3, 0)).json()
    assert cont["sequence_audit"]["anomalies"] == []
    assert cont["sequence_audit"]["last_sequence"] == 5
    assert cont["sequence_audit"]["suspected_gaps"] == 1


def test_import_preserves_wide_audit_values_beyond_signed_64_bits(db_path, tmp_path):
    src = make_client(db_path)
    register_u64(src)
    sid = make_session(
        src,
        {"protocol_id": "sensor-line64", "version": 1, "sequence_audit": True},
    )
    chunk = frame64(0) + frame64(INT64_MAX) + frame64(0) + frame64(INT64_MAX)
    d = append(src, sid, 0, chunk).json()
    assert d["sequence_audit"]["missing_total"] == (1 << 64) - 4
    cp = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    register_u64(dst)
    assert import_checkpoint(dst, cp).status_code == 201
    audit = dst.get(f"/sessions/{sid}").json()["sequence_audit"]
    assert audit["missing_total"] == 18446744073709551612
    assert audit["last_sequence"] == INT64_MAX

    # Stored as exact decimal text in the target database (not lossy REAL).
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "target.db"))
    stored_missing, stored_last = conn.execute(
        "SELECT audit_missing_total, audit_last_sequence FROM sessions"
    ).fetchone()
    conn.close()
    assert stored_missing == "18446744073709551612"
    assert isinstance(stored_missing, str)
    assert stored_last == str(INT64_MAX)

    # The replay after import is exact as well.
    replay = append(dst, sid, 0, chunk).json()
    assert replay["replayed"] is True
    assert replay["sequence_audit"]["missing_total"] == (1 << 64) - 4


def test_imported_session_survives_target_restart(db_path, tmp_path):
    target = str(tmp_path / "target.db")
    src = make_client(db_path)
    register_standard(src)
    sid, first_chunk = _seed_split_session(src)
    cp = export_checkpoint(src, sid)

    dst = make_client(target)
    register_standard(dst)
    assert import_checkpoint(dst, cp).status_code == 201

    # Restart the target service on the same file: state and replay survive.
    dst2 = make_client(target)
    replay = append(dst2, sid, 0, first_chunk).json()
    assert replay["replayed"] is True
    assert replay["frames_total"] == 1
    rest = b"\x55" + build_logical(2, 3, 0)
    cont = append(dst2, sid, len(first_chunk), rest).json()
    assert cont["frames"][0]["sequence"] == 2
    assert cont["frames_total"] == 2


# ---------------------------------------------------------- import guards ---


def test_existing_target_session_blocks_import_without_overwrite(db_path, tmp_path):
    src = make_client(db_path)
    register_standard(src)
    sid, _ = _seed_split_session(src)
    cp = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst)
    assert import_checkpoint(dst, cp).status_code == 201
    progress_before = dst.get(f"/sessions/{sid}").json()

    r = import_checkpoint(dst, cp)
    assert r.status_code == 409
    err = r.json()["error"]
    assert err["code"] == "SESSION_IMPORT_CONFLICT"
    assert err["details"]["reason"] == "session_exists"
    # The existing state is byte-for-byte unchanged.
    assert dst.get(f"/sessions/{sid}").json() == progress_before


def test_different_protocol_definition_blocks_import(db_path, tmp_path):
    src = make_client(db_path)
    register_standard(src)
    sid = make_session(src, {"protocol_id": "sensor-line", "version": 1})
    cp = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    # Same protocol id/version but a different definition (CRC offset moved).
    register_standard(dst, crc={"preset": "CRC-16/CCITT-FALSE", "offset": 5})
    r = import_checkpoint(dst, cp)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "SESSION_IMPORT_INVALID"
    assert err["details"]["reason"] == "protocol_mismatch"
    assert dst.get(f"/sessions/{sid}").status_code == 404


def test_tampered_checkpoints_are_rejected_and_leave_state_untouched(
    db_path, tmp_path
):
    src = make_client(db_path)
    register_standard(src)
    sid, _ = _seed_split_session(src)
    good = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst)
    assert import_checkpoint(dst, good).status_code == 201
    before = dst.get(f"/sessions/{sid}").json()

    def tampered(mutate):
        bad = copy.deepcopy(good)
        mutate(bad)
        return import_checkpoint(dst, bad)

    r = tampered(lambda cp: cp.update(received_offset=cp["received_offset"] + 1))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SESSION_IMPORT_INVALID"

    r = tampered(lambda cp: cp.__setitem__("frames_total", 999))
    assert r.status_code == 422

    r = tampered(lambda cp: cp["last_response"].__setitem__("next_offset", 1))
    assert r.status_code == 422
    assert any(
        "next_offset" in p
        for p in r.json()["error"]["details"]["problems"]
    )

    r = tampered(lambda cp: cp.update(tail_b64=b64(b"\x00" * 500)))
    assert r.status_code == 422  # tail longer than received_offset

    r = tampered(lambda cp: cp.update(format_version=99))
    assert r.status_code == 422
    assert any(
        "format_version" in p
        for p in r.json()["error"]["details"]["problems"]
    )

    r = tampered(lambda cp: cp.update(session_id="deadbeef"))
    assert r.status_code == 422

    r = tampered(lambda cp: cp.update(definition_sha256="z" * 64))
    assert r.status_code == 422

    r = tampered(lambda cp: cp.update(unknown_top_level_field=1))
    assert r.status_code == 422

    # None of the rejected imports changed the already-imported session.
    assert dst.get(f"/sessions/{sid}").json() == before


def test_failed_import_into_empty_target_persists_nothing(db_path, tmp_path):
    src = make_client(db_path)
    register_standard(src)
    sid, _ = _seed_split_session(src)
    good = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst)
    bad = copy.deepcopy(good)
    bad["last_response"]["frames_total"] = 42
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422

    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "target.db"))
    count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    conn.close()
    assert count == 0
    # The valid checkpoint still imports cleanly afterwards.
    assert import_checkpoint(dst, good).status_code == 201


def test_invalid_json_body_is_422(db_path):
    client = make_client(db_path)
    r = client.post(
        "/sessions/import",
        content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "INVALID_JSON"


def test_non_object_body_is_422(db_path):
    client = make_client(db_path)
    r = client.post("/sessions/import", json=[1, 2, 3])
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SESSION_IMPORT_INVALID"


def test_audit_envelope_contradictions_are_rejected(db_path, tmp_path):
    src = make_client(db_path)
    register_standard(src)
    sid = make_session(
        src, {"protocol_id": "sensor-line", "version": 1, "sequence_audit": True}
    )
    append(src, sid, 0, SYNC + build_logical(1, 3, 0))
    good = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst)

    # Audit block missing while audit_enabled is true.
    bad = copy.deepcopy(good)
    del bad["sequence_audit"]
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422
    assert any("sequence_audit" in p for p in r.json()["error"]["details"]["problems"])

    # Floats where exact integers are required are refused (no silent coercion).
    bad = copy.deepcopy(good)
    bad["frames_total"] = 1.5
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422


def test_cross_process_import_race_loses_cleanly(tmp_path):
    """A same-id INSERT racing a peer process hits the PRIMARY KEY.

    The existence check and the INSERT run in one transaction, but another
    process sharing the file can still commit between them. The loser must
    surface ``session_exists`` (-> 409), not a 500 integrity error.
    """
    target = str(tmp_path / "target.db")
    dst = make_client(target)
    register_standard(dst)

    src = make_client(str(tmp_path / "src.db"))
    register_standard(src)
    sid = make_session(src, {"protocol_id": "sensor-line", "version": 1})
    cp = export_checkpoint(src, sid)

    # First import lands normally.
    assert import_checkpoint(dst, cp).status_code == 201

    # Second import: hide the existing row from the existence check while the
    # PRIMARY KEY still sees it, so only the INSERT constraint can stop it.
    import sqlite3

    db = dst.app.state.db
    inner = db.conn

    class _RacyConnection:
        def __enter__(self):
            return inner.__enter__()

        def __exit__(self, exc_type, exc, tb):
            return inner.__exit__(exc_type, exc, tb)

        def execute(self, sql, params=()):
            if "SELECT 1 FROM sessions" in sql:
                return inner.execute("SELECT 1 FROM sessions WHERE 0")
            if sql.lstrip().startswith("INSERT INTO sessions"):
                raise sqlite3.IntegrityError(
                    "UNIQUE constraint failed: sessions.session_id"
                )
            return inner.execute(sql, params)

        def __getattr__(self, name):
            return getattr(inner, name)

    db._local.conn = _RacyConnection()
    result = db.import_session_checkpoint(
        session_id=cp["session_id"],
        protocol_id=cp["protocol_id"],
        version=cp["version"],
        definition_sha=cp["definition_sha256"],
        received_offset=cp["received_offset"],
        tail_b64=cp["tail_b64"],
        frames_total=cp["frames_total"],
        last_chunk_offset=cp["last_chunk_offset"],
        last_chunk_sha=cp["last_chunk_sha256"],
        last_response_json="",
        audit_enabled=False,
        audit_bit_width=None,
        audit_last_sequence=None,
        audit_duplicates=0,
        audit_suspected_gaps=0,
        audit_backwards=0,
        audit_indeterminates=0,
        audit_missing_total=0,
    )
    assert result == "session_exists"
    db._local.conn = inner

    # The rolled-back import changed nothing; the original session is intact.
    progress = dst.get(f"/sessions/{sid}").json()
    assert progress["received_offset"] == 0


# ------------------------------------------------- modulus / tail hardening ----


def _audit_checkpoint(client_factory, db_path, tmp_path):
    """Build a target client and an exported audit-enabled checkpoint."""
    src = client_factory(db_path)
    register_standard(src)
    sid = make_session(
        src, {"protocol_id": "sensor-line", "version": 1, "sequence_audit": True}
    )
    chunk = b"\x12" + SYNC + build_logical(1, 3, 2345) + b"\xaa"
    assert append(src, sid, 0, chunk).status_code == 200
    cp = export_checkpoint(src, sid)

    dst = client_factory(str(tmp_path / "target.db"))
    register_standard(dst)
    return dst, cp, sid, chunk


def test_widthed_checkpoint_with_tampered_modulus_is_rejected(db_path, tmp_path):
    """An 8-bit sequence field carried with bit_width 2 must never import.

    Both the top-level block and the stored response are forged to 2 so the
    checkpoint is internally self-consistent but contradicts the target
    protocol's effective sequence-field width. Importing would resume the
    audit against modulus 4 instead of 256; it must fail with 422 and write
    nothing.
    """
    dst, cp, sid, _ = _audit_checkpoint(make_client, db_path, tmp_path)
    bad = copy.deepcopy(cp)
    bad["sequence_audit"]["bit_width"] = 2
    bad["last_response"]["sequence_audit"]["bit_width"] = 2

    r = import_checkpoint(dst, bad)
    assert r.status_code == 422, r.text
    err = r.json()["error"]
    assert err["code"] == "SESSION_IMPORT_INVALID"
    assert err["details"]["reason"] == "audit_mismatch"
    assert err["details"]["checkpoint_bit_width"] == 2
    assert err["details"]["target_bit_width"] == 8
    assert dst.get(f"/sessions/{sid}").status_code == 404

    conn = sqlite3.connect(dst.app.state.settings.db_path)
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    conn.close()

    # The intact 8-bit checkpoint imports once the forged one is refused.
    assert import_checkpoint(dst, cp).status_code == 201


def test_structural_modulus_tamper_never_reaches_database(db_path, tmp_path):
    """Flipping only the top-level modulus contradicts the stored response:
    rejected structurally (details.problems) with no database access."""
    dst, cp, sid, _ = _audit_checkpoint(make_client, db_path, tmp_path)
    bad = copy.deepcopy(cp)
    bad["sequence_audit"]["bit_width"] = 2

    r = import_checkpoint(dst, bad)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "SESSION_IMPORT_INVALID"
    assert "reason" not in err.get("details", {})
    assert any("bit_width" in p for p in err["details"]["problems"])
    assert dst.get(f"/sessions/{sid}").status_code == 404


def test_audit_baseline_outside_modulus_range_is_rejected(db_path, tmp_path):
    dst, cp, sid, _ = _audit_checkpoint(make_client, db_path, tmp_path)
    for forge in (
        lambda c: c["sequence_audit"].__setitem__("last_sequence", 256),
        lambda c: c["sequence_audit"].__setitem__("last_sequence", -1),
        lambda c: c["last_response"]["frames"][0].__setitem__("sequence", 256),
    ):
        bad = copy.deepcopy(cp)
        forge(bad)
        r = import_checkpoint(dst, bad)
        assert r.status_code == 422, r.text
        assert r.json()["error"]["code"] == "SESSION_IMPORT_INVALID"
        assert dst.get(f"/sessions/{sid}").status_code == 404


def test_shifted_response_tail_start_is_rejected(db_path, tmp_path):
    """tail.start must equal received_offset minus the *decoded* tail length.

    A smaller but still in-range (start < end) value previously slipped
    through and would resume decoding from the wrong session position.
    """
    dst, cp, sid, _ = _audit_checkpoint(make_client, db_path, tmp_path)
    received = cp["received_offset"]

    bad = copy.deepcopy(cp)
    bad["last_response"]["tail"]["start"] = received - 2  # tail is 1 byte
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "SESSION_IMPORT_INVALID"
    assert any("tail.start" in p for p in err["details"]["problems"])
    assert dst.get(f"/sessions/{sid}").status_code == 404

    # Padding the response tail payload only (checkpoint tail unchanged) is
    # likewise a contradiction and must not import.
    bad = copy.deepcopy(cp)
    bad["last_response"]["tail"]["payload_b64"] = b64(b"\x00\x00")
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422
    assert dst.get(f"/sessions/{sid}").status_code == 404

    # The genuine checkpoint still imports afterwards.
    assert import_checkpoint(dst, cp).status_code == 201
    assert dst.get(f"/sessions/{sid}").json()["tail"]["start"] == received - 1


def test_valid_audit_checkpoint_replays_and_continues_after_hardening(
    db_path, tmp_path
):
    """The widened checks must not reject a real exported audit checkpoint:
    original id, replay, cross-shard continuation and 8-bit modulus survive."""
    dst, cp, sid, first_chunk = _audit_checkpoint(make_client, db_path, tmp_path)
    assert import_checkpoint(dst, cp).status_code == 201

    replay = append(dst, sid, 0, first_chunk).json()
    assert replay["replayed"] is True
    assert replay["frames_total"] == 1
    assert replay["sequence_audit"]["bit_width"] == 8

    rest = b"\x55" + build_logical(2, 3, 100)
    cont = append(dst, sid, len(first_chunk), rest).json()
    assert [f["sequence"] for f in cont["frames"]] == [2]
    assert cont["frames_total"] == 2
    assert cont["sequence_audit"]["bit_width"] == 8
    assert cont["sequence_audit"]["last_sequence"] == 2


def test_u64_checkpoint_modulus_checked_against_target_protocol(db_path, tmp_path):
    src = make_client(db_path)
    register_u64(src)
    sid = make_session(
        src,
        {"protocol_id": "sensor-line64", "version": 1, "sequence_audit": True},
    )
    assert append(src, sid, 0, frame64(0) + frame64(1)).status_code == 200
    cp = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    register_u64(dst)

    # Forge the modulus down to 8 everywhere (internally consistent, wrong).
    bad = copy.deepcopy(cp)
    bad["sequence_audit"]["bit_width"] = 8
    for frame in bad["last_response"]["frames"]:
        frame["sequence"] = frame["sequence"] & 0xFF
    bad["last_response"]["sequence_audit"]["bit_width"] = 8
    bad["last_response"]["sequence_audit"]["last_sequence"] = 1
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422
    assert r.json()["error"]["details"]["reason"] == "audit_mismatch"
    assert r.json()["error"]["details"]["target_bit_width"] == 64
    assert dst.get(f"/sessions/{sid}").status_code == 404

    assert import_checkpoint(dst, cp).status_code == 201


def test_non_audit_checkpoint_is_not_subjected_to_modulus_checks(
    db_path, tmp_path
):
    """Audit-disabled sessions carry no modulus; their import is unchanged."""
    src = make_client(db_path)
    register_standard(src)
    sid = make_session(src, {"protocol_id": "sensor-line", "version": 1})
    cp = export_checkpoint(src, sid)

    dst = make_client(str(tmp_path / "target.db"))
    # Register the same protocol definition but without any sequence field.
    register_standard(dst, sequence_field=None)
    # The definition digest differs, so this is protocol_mismatch — but a
    # normal identical registration imports the non-audit checkpoint fine.
    r = import_checkpoint(dst, cp)
    assert r.status_code == 422
    assert r.json()["error"]["details"]["reason"] == "protocol_mismatch"

    dst2 = make_client(str(tmp_path / "target2.db"))
    register_standard(dst2)
    assert import_checkpoint(dst2, cp).status_code == 201


def test_concurrent_protocol_registration_cannot_bypass_verification(
    db_path, tmp_path
):
    """Protocol verification and the session INSERT share one write txn.

    While an import holds the database write lock, a peer connection trying
    to register the same protocol version blocks until the import transaction
    ends; it can never change the protocol row the import verified or make a
    protocol appear inside that window.
    """
    from app import db as dbmod

    target = str(tmp_path / "target.db")
    dst = make_client(target)

    src = make_client(db_path)
    register_standard(src)
    sid = make_session(
        src, {"protocol_id": "sensor-line", "version": 1, "sequence_audit": True}
    )
    append(src, sid, 0, SYNC + build_logical(1, 3, 0))
    cp = export_checkpoint(src, sid)

    entered = threading.Event()
    release = threading.Event()
    armed = {"on": True}
    real_connect = dbmod._connect

    class _GatedConnection:
        """Proxy that stalls the import's BEGIN IMMEDIATE until released."""

        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, params=()):
            result = self._inner.execute(sql, params)
            if (
                armed["on"]
                and isinstance(sql, str)
                and sql.lstrip().upper().startswith("BEGIN IMMEDIATE")
            ):
                # Signal only once the write lock is actually held; then keep
                # the verified transaction open with the lock in its grasp.
                armed["on"] = False
                entered.set()
                release.wait(timeout=10)
            return result

        def __enter__(self):
            return self._inner.__enter__()

        def __exit__(self, exc_type, exc, tb):
            return self._inner.__exit__(exc_type, exc, tb)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    def gated_connect(path, **kwargs):
        return _GatedConnection(real_connect(path, **kwargs))

    result = {}

    def do_import():
        result["response"] = import_checkpoint(dst, cp)

    dbmod._connect = gated_connect
    t = threading.Thread(target=do_import)
    t.start()
    try:
        assert entered.wait(timeout=10)
        # The import now holds the write lock with NO protocol registered.
        # A peer process on the same file cannot insert one concurrently:
        # its write blocks on the lock instead of committing mid-import.
        peer_started = threading.Event()

        def peer_register():
            conn = sqlite3.connect(target, timeout=0.5, check_same_thread=True)
            try:
                conn.execute("PRAGMA busy_timeout=500")
                peer_started.set()
                conn.execute(
                    "INSERT OR REPLACE INTO protocols "
                    "(protocol_id, version, definition, definition_sha256) "
                    "VALUES (?, ?, ?, ?)",
                    ("sensor-line", 1, "{}", "a" * 64),
                )
                conn.commit()
                result["peer"] = "committed"
            except sqlite3.OperationalError:
                result["peer"] = "locked"
            finally:
                conn.close()

        rt = threading.Thread(target=peer_register)
        rt.start()
        assert peer_started.wait(timeout=10)
        assert not rt.join(timeout=1.0)  # still blocked on the write lock

        release.set()
        t.join(timeout=10)
        rt.join(timeout=10)
    finally:
        release.set()
        t.join(timeout=10)
        dbmod._connect = real_connect

    # Import was refused (protocol_mismatch): the peer registration could not
    # make it pass from inside the same verification transaction.
    assert result["response"].status_code == 422
    assert result["response"].json()["error"]["details"]["reason"] == (
        "protocol_mismatch"
    )
    assert dst.get(f"/sessions/{sid}").status_code == 404


def test_registration_committed_after_import_lock_releases_is_reverified(
    db_path, tmp_path
):
    """A registration blocked on the import lock cannot satisfy the check.

    The exact protocol is registered by a peer only after the import
    transaction has started and already observed its absence. Because the
    verification runs inside the locked write transaction, the peer's commit
    waits for the rollback and the import still fails; a subsequent import
    (seeing the now-committed protocol) succeeds instead.
    """
    from app import db as dbmod

    target = str(tmp_path / "target.db")
    dst = make_client(target)

    src = make_client(db_path)
    register_standard(src)
    sid = make_session(
        src, {"protocol_id": "sensor-line", "version": 1, "sequence_audit": True}
    )
    append(src, sid, 0, SYNC + build_logical(1, 3, 0))
    cp = export_checkpoint(src, sid)
    definition = src.get("/protocols/sensor-line?version=1").json()["definition"]

    entered = threading.Event()
    release = threading.Event()
    armed = {"on": True}
    real_connect = dbmod._connect

    class _GatedConnection:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, params=()):
            result = self._inner.execute(sql, params)
            if (
                armed["on"]
                and isinstance(sql, str)
                and sql.lstrip().upper().startswith("BEGIN IMMEDIATE")
            ):
                # Signal only once the write lock is actually held, then stall
                # the verified transaction with the lock in its possession.
                armed["on"] = False
                entered.set()
                release.wait(timeout=10)
            return result

        def __enter__(self):
            return self._inner.__enter__()

        def __exit__(self, exc_type, exc, tb):
            return self._inner.__exit__(exc_type, exc, tb)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    dbmod._connect = lambda path, **kw: _GatedConnection(real_connect(path, **kw))
    result = {}
    try:
        t = threading.Thread(
            target=lambda: result.update(response=import_checkpoint(dst, cp))
        )
        t.start()
        assert entered.wait(timeout=10)

        # Register the exact protocol via the normal API from another thread;
        # its write blocks while the gated import transaction is held open.
        registered = {}

        def register():
            registered["response"] = dst.post("/protocols", json=definition)

        rt = threading.Thread(target=register)
        rt.start()
        assert not rt.join(timeout=1.0)

        release.set()
        t.join(timeout=10)
        rt.join(timeout=10)
    finally:
        release.set()
        dbmod._connect = real_connect

    # First import verified before the peer registration committed: refused.
    assert result["response"].status_code == 422
    assert result["response"].json()["error"]["details"]["reason"] == (
        "protocol_mismatch"
    )
    assert registered["response"].status_code == 201

    # Once the registration is committed, a fresh import verifies against it
    # inside its own transaction and lands with the original session id.
    r = import_checkpoint(dst, cp)
    assert r.status_code == 201, r.text
    assert r.json()["session_id"] == sid
    assert r.json()["sequence_audit"]["bit_width"] == 8
