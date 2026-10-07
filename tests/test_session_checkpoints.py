"""Tests for session checkpoint HTTP export/import when swapping SQLite files.

A checkpoint exported from one database lets an existing collection session
continue in another database under its original ``session_id``:

* ``GET /sessions/{id}/checkpoint`` returns one committed snapshot: exact
  protocol version and definition digest, received offset, raw pending tail,
  cumulative frame count, last fragment digest and original response, and the
  sequence-audit progress when enabled;
* ``POST /sessions/import`` only accepts a checkpoint whose exact protocol
  version is registered in the target database with the identical definition
  digest, when no session with the same id exists there yet, and when the
  envelope is internally self-consistent (tail/offset and the stored response
  agree); failure never touches existing target state;
* after import, frames split across the migration boundary decode once, the
  sequence audit keeps its baseline, resending the last fragment replays the
  original response without double counting, and audit values past SQLite's
  signed 64-bit INTEGER range stay exact.
"""
from __future__ import annotations

import copy

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


def _audited_checkpoint(db_path):
    src = make_client(db_path)
    register_standard(src)
    sid = make_session(
        src, {"protocol_id": "sensor-line", "version": 1, "sequence_audit": True}
    )
    chunk = b"\x12" + SYNC + build_logical(1, 3, 2345) + b"\xaa"
    append(src, sid, 0, chunk)
    return src, sid, chunk, export_checkpoint(src, sid)


def test_tampered_audit_bit_width_is_rejected_against_target_protocol(
    db_path, tmp_path
):
    """Both bit_width copies at 2 must not import when the target field is 8."""
    _, sid, chunk, good = _audited_checkpoint(db_path)

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst)

    bad = copy.deepcopy(good)
    bad["sequence_audit"]["bit_width"] = 2
    bad["last_response"]["sequence_audit"]["bit_width"] = 2
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422, r.text
    err = r.json()["error"]
    assert err["code"] == "SESSION_IMPORT_INVALID"
    assert err["details"]["reason"] == "audit_bit_width_mismatch"
    assert err["details"]["target_bit_width"] == 8
    assert err["details"]["checkpoint_bit_width"] == 2
    assert dst.get(f"/sessions/{sid}").status_code == 404

    # Nothing landed; the intact checkpoint imports and subsequent appends use
    # the protocol's true modulus (256), not the tampered 4.
    assert import_checkpoint(dst, good).status_code == 201
    cont = append(
        dst,
        sid,
        len(chunk),
        b"\x55" + build_logical(2, 3, 100),
    ).json()
    assert cont["frames"][0]["sequence"] == 2
    assert cont["sequence_audit"]["bit_width"] == 8
    # seq 1 -> 2 is one normal step modulo 256 (it would be a suspected gap
    # modulo 4), proving the audit modulus came from the target protocol.
    assert cont["sequence_audit"]["suspected_gaps"] == 0


def test_tail_start_other_than_offset_minus_tail_bytes_is_rejected(
    db_path, tmp_path
):
    _, sid, _, good = _audited_checkpoint(db_path)
    correct_start = good["last_response"]["tail"]["start"]

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst)

    # One byte earlier: still <= end, but the tail window would re-attach an
    # already accepted byte when the response is replayed.
    bad = copy.deepcopy(good)
    bad["last_response"]["tail"]["start"] = correct_start - 1
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422
    problems = r.json()["error"]["details"]["problems"]
    assert any("tail.start" in p for p in problems)
    assert dst.get(f"/sessions/{sid}").status_code == 404

    # One byte later (a start past the true window, still not past end here
    # because the tail is exactly one byte: start == end) is rejected too.
    bad = copy.deepcopy(good)
    bad["last_response"]["tail"]["start"] = correct_start + 1
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422
    assert any("tail.start" in p for p in r.json()["error"]["details"]["problems"])

    assert import_checkpoint(dst, good).status_code == 201


def test_out_of_range_baseline_sequence_is_rejected(db_path, tmp_path):
    _, sid, _, good = _audited_checkpoint(db_path)
    assert good["sequence_audit"]["bit_width"] == 8

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst)

    bad = copy.deepcopy(good)
    bad["sequence_audit"]["last_sequence"] = 256
    bad["last_response"]["sequence_audit"]["last_sequence"] = 256
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "SESSION_IMPORT_INVALID"
    assert err["details"]["reason"] == "audit_sequence_out_of_range"
    assert err["details"]["max_sequence"] == 255
    assert dst.get(f"/sessions/{sid}").status_code == 404

    # 0..255 is the accepted baseline range.
    ok = copy.deepcopy(good)
    ok["sequence_audit"]["last_sequence"] = 255
    ok["last_response"]["sequence_audit"]["last_sequence"] = 255
    assert import_checkpoint(dst, ok).status_code == 201


def test_target_protocol_without_valid_sequence_field_rejects_audited_checkpoint(
    db_path, tmp_path
):
    """No usable unsigned sequence field under the pinned digest fails import.

    The checkpoint carries an audit block and names a digest the target really
    has registered, but the registered protocol declares no valid unsigned
    sequence field. The audit must not be silently dropped; the import fails
    inside the verification transaction.
    """
    _, sid, _, good = _audited_checkpoint(db_path)

    dst = make_client(str(tmp_path / "target.db"))
    register_standard(dst, **{"sequence_field": None})

    # The checkpoint claims the digest of the target's sequence-less protocol.
    bad = copy.deepcopy(good)
    bad["definition_sha256"] = dst.get("/protocols").json()["protocols"][0][
        "definition_sha256"
    ]
    r = import_checkpoint(dst, bad)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "SESSION_IMPORT_INVALID"
    assert err["details"]["reason"] == "audit_field_unsupported"
    assert err["details"]["target_bit_width"] is None
    assert dst.get(f"/sessions/{sid}").status_code == 404


def test_import_verification_and_insert_share_one_write_transaction(
    db_path, tmp_path
):
    """The import opens BEGIN IMMEDIATE before any verification read.

    A competing protocol registration from another connection sharing the
    file must wait for the import's write lock, so the digest/bit-width checks
    and the session INSERT are one serialized critical section.
    """
    import sqlite3
    import threading
    import time

    import app.db as dbmod

    _, _, _, cp = _audited_checkpoint(db_path)
    target = str(tmp_path / "target.db")
    dst = make_client(target)
    register_standard(dst)

    # Statements executed on the import connection, in arrival order.
    events: list[str] = []
    db = dst.app.state.db
    inner = db.conn

    class _TracingConnection:
        def execute(self, sql, params=()):
            head = sql.lstrip()
            for tag in (
                "BEGIN",
                "SELECT definition",
                "SELECT 1 FROM sessions",
                "INSERT INTO sessions",
                "COMMIT",
            ):
                if head.startswith(tag):
                    events.append(tag)
            return inner.execute(sql, params)

        def __setattr__(self, name, value):
            # Transaction control attributes must reach the real connection.
            if name == "isolation_level":
                setattr(inner, name, value)
            else:
                object.__setattr__(self, name, value)

        def __getattr__(self, name):
            return getattr(inner, name)

    db._local.conn = _TracingConnection()
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
        audit_enabled=True,
        audit_bit_width=cp["sequence_audit"]["bit_width"],
        audit_last_sequence=cp["sequence_audit"]["last_sequence"],
        audit_duplicates=0,
        audit_suspected_gaps=0,
        audit_backwards=0,
        audit_indeterminates=0,
        audit_missing_total=0,
    )
    db._local.conn = inner
    assert result == "imported"
    assert events[0] == "BEGIN"
    assert events.index("SELECT definition") < events.index("INSERT INTO sessions")
    assert events[-1] == "COMMIT"

    # While a writer holds the database write lock, a protocol registration
    # from a second shared connection blocks until the import-style txn ends.
    locker = dbmod._connect(target)
    locker.isolation_level = None
    locker.execute("BEGIN IMMEDIATE")

    second = make_client(target)
    registered = threading.Event()

    def register():
        from app.models import ProtocolDefinition

        other = standard_protocol(protocol_id="other-line")
        second.app.state.db.upsert_protocol(
            ProtocolDefinition.model_validate(other), "0" * 64
        )
        registered.set()

    t = threading.Thread(target=register)
    t.start()
    assert not registered.wait(0.7), "registration bypassed the held write lock"
    locker.execute("ROLLBACK")
    locker.close()
    assert registered.wait(5)
    t.join(5)


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
