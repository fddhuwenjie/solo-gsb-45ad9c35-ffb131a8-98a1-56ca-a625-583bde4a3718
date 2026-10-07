"""Tests for the optional per-session sequence continuity audit.

Audit semantics under test:

* enabling is per session at creation time; the pinned protocol must declare
  ``sequence_field`` naming an unsigned integer field with an effective bit
  width of at least 2, otherwise creation is rejected 422
  ``SEQUENCE_AUDIT_UNSUPPORTED``; sessions without the flag are untouched;
* each successful append judges only its newly confirmed frames, comparing
  raw sequences modulo 2**bit_width: same -> duplicate, one step -> normal,
  2..half-1 steps -> suspected gap with a missing count, more than half a
  turn -> backward, exactly half a turn -> indeterminate (the last two infer
  no missing frames);
* every valid frame becomes the next comparison baseline; bad frames and the
  pending tail never move it;
* the audit state commits atomically with the shard state and the response:
  same-chunk retries replay the stored audit block, conflicts and decode
  errors change nothing, and a restart resumes from the persisted baseline.
"""
from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import b64, build_logical, standard_protocol

SYNC = b"\xaa\x55"
FRAME_LEN = len(SYNC) + 9  # standard protocol wire frame: sync + 9-byte body
AMBIGUOUS = bytes.fromhex("67aa55710aaa550c7845ca08aab4be")


def register(client, **overrides):
    r = client.post("/protocols", json=standard_protocol(**overrides))
    assert r.status_code == 201, r.text
    return r


def make_session(client, protocol_id="sensor-line", version=1, audit=True):
    payload = {"protocol_id": protocol_id, "version": version}
    if audit is not None:
        payload["sequence_audit"] = audit
    r = client.post("/sessions", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


def append(client, sid, offset, chunk):
    return client.post(
        "/sessions/append",
        json={"session_id": sid, "expected_offset": offset, "chunk_b64": b64(chunk)},
    )


def frame(seq, addr=3, temp=0):
    return SYNC + build_logical(seq, addr, temp)


def corrupt(wire: bytes, wire_offset: int = 5) -> bytes:
    """Flip one CRC-covered payload byte so the frame fails its CRC check."""
    bad = bytearray(wire)
    bad[wire_offset] ^= 0xFF
    return bytes(bad)


def audit_of(client, sid):
    return client.get(f"/sessions/{sid}").json()["sequence_audit"]


# ------------------------------------------------------------- creation ------


def test_audit_creation_requires_usable_sequence_field(client):
    # No sequence_field declared at all.
    register(client, protocol_id="no-seq", sequence_field=None)
    r = client.post(
        "/sessions",
        json={"protocol_id": "no-seq", "version": 1, "sequence_audit": True},
    )
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "SEQUENCE_AUDIT_UNSUPPORTED"
    assert err["details"]["sequence_field"] is None
    assert err["details"]["bit_width"] is None
    assert err["details"]["min_bit_width"] == 2

    # Signed storage type.
    register(
        client,
        protocol_id="signed-seq",
        fields=[{"name": "seq", "type": "s8", "offset": 0}],
    )
    r = client.post(
        "/sessions",
        json={"protocol_id": "signed-seq", "version": 1, "sequence_audit": True},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SEQUENCE_AUDIT_UNSUPPORTED"

    # Unsigned type but flagged signed.
    register(
        client,
        protocol_id="signed-flag",
        fields=[{"name": "seq", "type": "u8", "offset": 0, "signed": True}],
    )
    r = client.post(
        "/sessions",
        json={"protocol_id": "signed-flag", "version": 1, "sequence_audit": True},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SEQUENCE_AUDIT_UNSUPPORTED"

    # Effective bit width below two (1-bit bit-field).
    register(
        client,
        protocol_id="one-bit",
        fields=[{"name": "seq", "type": "u8", "offset": 0, "bit_offset": 0, "bit_width": 1}],
    )
    r = client.post(
        "/sessions",
        json={"protocol_id": "one-bit", "version": 1, "sequence_audit": True},
    )
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "SEQUENCE_AUDIT_UNSUPPORTED"
    assert err["details"]["bit_width"] == 1


def test_audit_creation_accepts_two_bits_and_reports_width(client):
    register(
        client,
        protocol_id="two-bit",
        fields=[{"name": "seq", "type": "u8", "offset": 0, "bit_offset": 0, "bit_width": 2}],
    )
    r = client.post(
        "/sessions",
        json={"protocol_id": "two-bit", "version": 1, "sequence_audit": True},
    )
    assert r.status_code == 201, r.text
    audit = r.json()["sequence_audit"]
    assert audit["bit_width"] == 2
    assert audit["last_sequence"] is None
    assert audit["duplicates"] == audit["suspected_gaps"] == 0
    assert audit["backwards"] == audit["indeterminates"] == 0
    assert audit["missing_total"] == 0

    # Plain u8 sequence field: full storage width (8 bits).
    register(client)
    s = make_session(client)
    assert s["sequence_audit"]["bit_width"] == 8


def test_session_without_audit_is_unchanged(client):
    register(client, protocol_id="no-seq", sequence_field=None)

    # Default (flag omitted): no audit block anywhere, even without a
    # declared sequence field.
    r = client.post("/sessions", json={"protocol_id": "no-seq", "version": 1})
    assert r.status_code == 201, r.text
    assert "sequence_audit" not in r.json()
    sid = r.json()["session_id"]

    # Duplicate sequences pass unaudited.
    d = append(client, sid, 0, frame(1) + frame(1)).json()
    assert d["frames_total"] == 2
    assert d["sequence_audit"] is None
    assert client.get(f"/sessions/{sid}").json()["sequence_audit"] is None

    # Explicitly disabled behaves the same.
    r = client.post(
        "/sessions",
        json={"protocol_id": "sensor-line", "version": 1, "sequence_audit": False},
    )
    assert "sequence_audit" not in r.json()


# --------------------------------------------------------- classification ----


def test_clean_sequence_and_wraparound_have_no_anomalies(client):
    register(client)
    sid = make_session(client)["session_id"]

    d1 = append(client, sid, 0, frame(254) + frame(255)).json()
    assert d1["sequence_audit"]["anomalies"] == []
    assert d1["sequence_audit"]["last_sequence"] == 255

    # Wrapping past the modulus (255 -> 0 -> 1) is a normal one-step advance.
    d2 = append(client, sid, d1["next_offset"], frame(0) + frame(1)).json()
    audit = d2["sequence_audit"]
    assert audit["anomalies"] == []
    assert audit["last_sequence"] == 1
    assert audit["duplicates"] == audit["suspected_gaps"] == 0
    assert audit["backwards"] == audit["indeterminates"] == 0
    assert audit["missing_total"] == 0


def test_duplicate_sequence(client):
    register(client)
    sid = make_session(client)["session_id"]

    d1 = append(client, sid, 0, frame(5)).json()
    assert d1["sequence_audit"]["anomalies"] == []  # first frame only rebases

    d2 = append(client, sid, d1["next_offset"], frame(5)).json()
    (anomaly,) = d2["sequence_audit"]["anomalies"]
    assert anomaly["type"] == "duplicate"
    assert anomaly["frame_start"] == FRAME_LEN
    assert anomaly["frame_end"] == 2 * FRAME_LEN
    assert anomaly["previous_sequence"] == 5
    assert anomaly["sequence"] == 5
    assert anomaly["missing"] is None
    assert d2["sequence_audit"]["duplicates"] == 1

    # The duplicate itself is the new baseline: a third 5 duplicates again.
    d3 = append(client, sid, d2["next_offset"], frame(5)).json()
    assert [a["type"] for a in d3["sequence_audit"]["anomalies"]] == ["duplicate"]
    assert d3["sequence_audit"]["duplicates"] == 2


def test_suspected_gap_reports_missing_count(client):
    register(client)
    sid = make_session(client)["session_id"]

    d = append(client, sid, 0, frame(1) + frame(4)).json()
    (anomaly,) = d["sequence_audit"]["anomalies"]
    assert anomaly["type"] == "suspected_gap"
    assert anomaly["previous_sequence"] == 1
    assert anomaly["sequence"] == 4
    assert anomaly["missing"] == 2
    assert anomaly["frame_start"] == FRAME_LEN
    audit = d["sequence_audit"]
    assert audit["suspected_gaps"] == 1
    assert audit["missing_total"] == 2


def test_wraparound_gap_uses_modulus(client):
    register(client)
    sid = make_session(client)["session_id"]

    d = append(client, sid, 0, frame(254) + frame(1)).json()
    (anomaly,) = d["sequence_audit"]["anomalies"]
    # (1 - 254) mod 256 = 3 steps forward -> two frames missing, not a
    # backward jump of 253.
    assert anomaly["type"] == "suspected_gap"
    assert anomaly["missing"] == 2


def test_backward_jump_infers_no_missing(client):
    register(client)
    sid = make_session(client)["session_id"]

    d = append(client, sid, 0, frame(100) + frame(50)).json()
    (anomaly,) = d["sequence_audit"]["anomalies"]
    # (50 - 100) mod 256 = 206 > 128 (half a turn) -> backward.
    assert anomaly["type"] == "backward"
    assert anomaly["missing"] is None
    audit = d["sequence_audit"]
    assert audit["backwards"] == 1
    assert audit["suspected_gaps"] == 0
    assert audit["missing_total"] == 0


def test_exactly_half_turn_is_indeterminate(client):
    register(client)
    sid = make_session(client)["session_id"]

    d = append(client, sid, 0, frame(0) + frame(128)).json()
    (anomaly,) = d["sequence_audit"]["anomalies"]
    assert anomaly["type"] == "indeterminate"
    assert anomaly["missing"] is None
    audit = d["sequence_audit"]
    assert audit["indeterminates"] == 1
    assert audit["missing_total"] == 0


def test_every_valid_frame_rebases_the_comparison(client):
    register(client)
    sid = make_session(client)["session_id"]

    d1 = append(client, sid, 0, frame(0) + frame(128)).json()
    assert [a["type"] for a in d1["sequence_audit"]["anomalies"]] == ["indeterminate"]

    # The half-turn frame became the baseline: 128 -> 129 is a normal step.
    d2 = append(client, sid, d1["next_offset"], frame(129)).json()
    assert d2["sequence_audit"]["anomalies"] == []
    assert d2["sequence_audit"]["last_sequence"] == 129
    assert d2["sequence_audit"]["indeterminates"] == 1


def test_bit_field_sequence_uses_its_bit_width(client):
    register(
        client,
        protocol_id="bit4-line",
        fields=[
            {"name": "seq", "type": "u8", "offset": 0, "bit_offset": 0, "bit_width": 4},
            {"name": "addr", "type": "u8", "offset": 1},
        ],
    )
    sid = make_session(client, protocol_id="bit4-line")["session_id"]

    # Modulus is 2**4 = 16: (1 - 14) mod 16 = 3 -> gap of 2, whereas a
    # byte-wide modulus would read the same pair as a backward jump.
    d1 = append(client, sid, 0, frame(14) + frame(1)).json()
    (anomaly,) = d1["sequence_audit"]["anomalies"]
    assert anomaly["type"] == "suspected_gap"
    assert anomaly["missing"] == 2
    assert d1["sequence_audit"]["bit_width"] == 4

    # Half of 16 is 8: 1 -> 9 is exactly half a turn.
    d2 = append(client, sid, d1["next_offset"], frame(9)).json()
    (anomaly,) = d2["sequence_audit"]["anomalies"]
    assert anomaly["type"] == "indeterminate"


# ------------------------------------------------------- baseline sources ----


def test_bad_frames_and_pending_tail_do_not_move_baseline(client):
    register(client)
    sid = make_session(client)["session_id"]

    # A CRC-broken frame carrying sequence 7 sits between valid 1 and 2; only
    # the valid frames may participate, so no anomaly is raised.
    chunk1 = frame(1) + corrupt(frame(7)) + frame(2)
    d1 = append(client, sid, 0, chunk1).json()
    assert [f["sequence"] for f in d1["frames"]] == [1, 2]
    assert d1["discarded"][0]["failed_attempts"][0]["error"] == "crc_failed"
    assert d1["sequence_audit"]["anomalies"] == []
    assert d1["sequence_audit"]["last_sequence"] == 2

    # A partial frame stays pending in the tail and is not audited yet.
    part = frame(9)[:4]
    d2 = append(client, sid, d1["next_offset"], part).json()
    assert d2["frame_count"] == 0
    assert d2["sequence_audit"]["anomalies"] == []
    assert d2["sequence_audit"]["last_sequence"] == 2

    # Once completed, the frame is judged against the last confirmed one.
    rest = frame(9)[4:] + frame(10)
    d3 = append(client, sid, d2["next_offset"], rest).json()
    assert [f["sequence"] for f in d3["frames"]] == [9, 10]
    (anomaly,) = d3["sequence_audit"]["anomalies"]
    assert anomaly["type"] == "suspected_gap"
    assert anomaly["previous_sequence"] == 2
    assert anomaly["sequence"] == 9
    assert anomaly["missing"] == 6
    # Offsets are cumulative session positions of the gap frame.
    assert anomaly["frame_start"] == 3 * FRAME_LEN
    assert anomaly["frame_end"] == 4 * FRAME_LEN
    assert d3["sequence_audit"]["last_sequence"] == 10


# ------------------------------------------- commit / replay / failure -------


def test_replay_returns_stored_audit_block_without_double_count(client):
    register(client)
    sid = make_session(client)["session_id"]
    chunk = frame(1) + frame(4)  # one suspected gap, two missing

    d1 = append(client, sid, 0, chunk).json()
    assert d1["sequence_audit"]["suspected_gaps"] == 1

    r2 = append(client, sid, 0, chunk)
    d2 = r2.json()
    assert r2.status_code == 200
    assert d2["replayed"] is True
    assert d2["sequence_audit"] == d1["sequence_audit"]

    audit = audit_of(client, sid)
    assert audit["suspected_gaps"] == 1
    assert audit["missing_total"] == 2
    assert audit["last_sequence"] == 4


def test_conflict_and_decode_error_leave_audit_untouched(client):
    register(client)
    sid = make_session(client)["session_id"]

    d1 = append(client, sid, 0, frame(1)).json()
    assert d1["sequence_audit"]["last_sequence"] == 1

    # Same offset, different content: 409, audit state unchanged.
    r = append(client, sid, 0, frame(2))
    assert r.status_code == 409
    # Decoder hard error: 422, audit state unchanged.
    r = append(client, sid, FRAME_LEN, AMBIGUOUS)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "AMBIGUOUS_FRAME"

    audit = audit_of(client, sid)
    assert audit["last_sequence"] == 1
    assert audit["duplicates"] == audit["suspected_gaps"] == 0
    assert audit["backwards"] == audit["indeterminates"] == 0
    assert audit["missing_total"] == 0

    # The session is still usable and the baseline is still sequence 1.
    d2 = append(client, sid, FRAME_LEN, frame(2)).json()
    assert d2["sequence_audit"]["anomalies"] == []
    assert d2["frames_total"] == 2


def test_restart_resumes_audit_state(db_path):
    chunk1 = frame(1) + frame(4)  # suspected gap, missing 2

    with TestClient(create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))) as c:
        register(c)
        sid = make_session(c)["session_id"]
        d1 = append(c, sid, 0, chunk1).json()
        assert d1["sequence_audit"]["suspected_gaps"] == 1

    # Simulate a service restart: a brand-new app on the same SQLite file.
    with TestClient(create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))) as c:
        audit = audit_of(c, sid)
        assert audit["bit_width"] == 8
        assert audit["last_sequence"] == 4
        assert audit["suspected_gaps"] == 1
        assert audit["missing_total"] == 2

        replay = append(c, sid, 0, chunk1).json()
        assert replay["replayed"] is True
        assert replay["sequence_audit"] == d1["sequence_audit"]

        # The persisted baseline (4) judges the next frame: 4 -> 4 duplicates.
        d2 = append(c, sid, replay["next_offset"], frame(4)).json()
        (anomaly,) = d2["sequence_audit"]["anomalies"]
        assert anomaly["type"] == "duplicate"
        assert anomaly["previous_sequence"] == 4
        assert d2["sequence_audit"]["duplicates"] == 1


# ------------------------------------------------------------- progress ------


def test_progress_reports_cumulative_counts_per_type(client):
    register(client)
    sid = make_session(client)["session_id"]

    d1 = append(client, sid, 0, frame(1) + frame(1) + frame(4)).json()
    a1 = d1["sequence_audit"]
    assert [x["type"] for x in a1["anomalies"]] == ["duplicate", "suspected_gap"]
    assert (a1["duplicates"], a1["suspected_gaps"], a1["missing_total"]) == (1, 1, 2)

    d2 = append(client, sid, d1["next_offset"], frame(132)).json()
    assert [x["type"] for x in d2["sequence_audit"]["anomalies"]] == ["indeterminate"]

    d3 = append(client, sid, d2["next_offset"], frame(5)).json()
    assert [x["type"] for x in d3["sequence_audit"]["anomalies"]] == ["backward"]

    audit = audit_of(client, sid)
    assert audit["last_sequence"] == 5
    assert audit["duplicates"] == 1
    assert audit["suspected_gaps"] == 1
    assert audit["backwards"] == 1
    assert audit["indeterminates"] == 1
    assert audit["missing_total"] == 2


# ------------------------------------------------------- existing databases --


def test_pre_upgrade_database_is_migrated_and_old_sessions_work(tmp_path):
    """A sessions table created before the audit columns existed is upgraded
    in place; its sessions keep working with the audit disabled."""
    db_file = tmp_path / "old.db"
    conn = sqlite3.connect(str(db_file))
    conn.executescript(
        """
        CREATE TABLE sessions (
            session_id        TEXT PRIMARY KEY,
            protocol_id       TEXT NOT NULL,
            version           INTEGER NOT NULL,
            received_offset   INTEGER NOT NULL,
            tail_b64          TEXT NOT NULL,
            frames_total      INTEGER NOT NULL DEFAULT 0,
            last_chunk_offset INTEGER,
            last_chunk_sha256 TEXT,
            last_response     TEXT NOT NULL,
            created_at        TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """
    )
    conn.execute(
        "INSERT INTO sessions "
        "(session_id, protocol_id, version, received_offset, tail_b64, "
        " frames_total, last_response) "
        "VALUES ('old-session', 'sensor-line', 1, 0, '', 0, '')"
    )
    conn.commit()
    conn.close()

    with TestClient(
        create_app(Settings(db_path=str(db_file), max_decode_bytes=1 << 20))
    ) as c:
        register(c)
        progress = c.get("/sessions/old-session").json()
        assert progress["received_offset"] == 0
        assert progress["sequence_audit"] is None

        d = append(c, "old-session", 0, frame(1) + frame(1)).json()
        assert d["frames_total"] == 2
        assert d["sequence_audit"] is None

        # New sessions on the same upgraded file can enable the audit.
        sid = make_session(c)["session_id"]
        d = append(c, sid, 0, frame(1) + frame(1)).json()
        assert d["sequence_audit"]["duplicates"] == 1


# ------------------------------------------------------------ multi-instance --


def make_instance(db_path):
    app = create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))
    return app, TestClient(app)


def gate_first_session_read(app, barrier):
    """Hold this instance's first session read until both instances read."""
    db = app.state.db
    real_get_session = db.get_session
    gated = False

    def get_session(session_id):
        nonlocal gated
        row = real_get_session(session_id)
        if not gated:
            gated = True
            barrier.wait(timeout=10)
        return row

    db.get_session = get_session


def test_two_instances_identical_chunk_race_counts_audit_once(db_path):
    app_a, client_a = make_instance(db_path)
    app_b, client_b = make_instance(db_path)
    with client_a, client_b:
        register(client_a)
        sid = make_session(client_a)["session_id"]

        chunk = frame(1) + frame(1)  # commits exactly one duplicate anomaly
        barrier = threading.Barrier(2)
        gate_first_session_read(app_a, barrier)
        gate_first_session_read(app_b, barrier)

        with ThreadPoolExecutor(max_workers=2) as pool:
            future_a = pool.submit(append, client_a, sid, 0, chunk)
            future_b = pool.submit(append, client_b, sid, 0, chunk)
            resp_a, resp_b = future_a.result(), future_b.result()

        assert resp_a.status_code == resp_b.status_code == 200
        bodies = [resp_a.json(), resp_b.json()]
        assert sorted(b["replayed"] for b in bodies) == [False, True]
        # The loser replays the stored response, audit block included.
        assert bodies[0]["sequence_audit"] == bodies[1]["sequence_audit"]

        # Both instances observe the anomaly counted exactly once.
        for client in (client_a, client_b):
            progress = client.get(f"/sessions/{sid}").json()
            assert progress["frames_total"] == 2
            audit = progress["sequence_audit"]
            assert audit["duplicates"] == 1
            assert audit["last_sequence"] == 1
