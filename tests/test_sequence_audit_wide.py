"""Boundary tests for the sequence audit at and beyond signed 64-bit values.

The raw sequence of a u64 sequence field can reach 2**63 and beyond, and the
cumulative inferred-missing counter grows without bound (a single suspected
gap at bit width 64 can infer almost 2**63 missing frames). SQLite's INTEGER
is a signed 64-bit value, so both are persisted as decimal text and decoded
back to exact Python ints. Under test:

* appends whose raw sequence reaches 2**63 .. 2**64-1 commit successfully,
  with exact anomaly details, byte offsets and cumulative counters;
* confirming 0, 2**63-1, 0, 2**63-1 accumulates a missing_total of
  2**64 - 4 — past the signed 64-bit maximum — and stays exact;
* the wide state commits atomically with the shard state: same-chunk retries
  replay the stored response, conflicts and decode failures move nothing,
  restarts and peer instances on the same database file resume the
  comparison from the persisted wide baseline;
* databases written while the wide columns were INTEGER are rebuilt in
  place: historical values read back unchanged and the session continues;
* sessions without the audit and the stateless /decode endpoint handle the
  same wide sequences unchanged.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import b64, crc_ccitt

SYNC = b"\xaa\x55"
FRAME64_LEN = len(SYNC) + 16  # sync + 16-byte logical body
INT64_MAX = (1 << 63) - 1
UINT64_MAX = (1 << 64) - 1


def u64_protocol(**overrides):
    """Protocol with a u64 sequence field: 16-byte logical body.

    Layout after the sync bytes: seq u64 @0, addr u8 @8, length u8 @12
    (value = logical length), CRC-16/CCITT-FALSE @14.
    """
    proto = {
        "protocol_id": "sensor-line64",
        "version": 1,
        "sync": [0xAA, 0x55],
        "endian": "big",
        "length_field": {"offset": 12, "size": 1, "adjustment": 0},
        "crc": {"preset": "CRC-16/CCITT-FALSE", "offset": 14},
        "fields": [
            {"name": "seq", "type": "u64", "offset": 0},
            {"name": "addr", "type": "u8", "offset": 8},
        ],
        "sequence_field": "seq",
        "max_frame_length": 64,
    }
    proto.update(overrides)
    return proto


def frame64(seq, addr=3):
    body = bytearray(16)
    body[0:8] = seq.to_bytes(8, "big")
    body[8] = addr & 0xFF
    body[12] = 16
    body[14:16] = crc_ccitt(bytes(body[:14])).to_bytes(2, "big")
    return SYNC + bytes(body)


def register(client, **overrides):
    r = client.post("/protocols", json=u64_protocol(**overrides))
    assert r.status_code == 201, r.text
    return r


def make_session(client, audit=True, protocol_id="sensor-line64", version=1):
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


def audit_of(client, sid):
    return client.get(f"/sessions/{sid}").json()["sequence_audit"]


# ------------------------------------------------------- wide sequences ----


def test_sequence_at_and_above_2_to_the_63_commits_exactly(client):
    register(client)
    sid = make_session(client)["session_id"]

    # 2**63 - 1 -> 2**63: a normal one-step advance across the signed
    # 64-bit boundary; the baseline itself no longer fits SQLite INTEGER.
    d1 = append(client, sid, 0, frame64(INT64_MAX) + frame64(1 << 63)).json()
    assert d1["frames"][1]["sequence"] == 1 << 63
    audit = d1["sequence_audit"]
    assert audit["anomalies"] == []
    assert audit["last_sequence"] == 1 << 63
    assert d1["next_offset"] == 2 * FRAME64_LEN

    # 2**63 -> 2**64 - 1: delta is half a turn minus one, a suspected gap
    # whose missing count is itself a wide integer.
    d2 = append(client, sid, d1["next_offset"], frame64(UINT64_MAX)).json()
    (anomaly,) = d2["sequence_audit"]["anomalies"]
    assert anomaly["type"] == "suspected_gap"
    assert anomaly["frame_start"] == 2 * FRAME64_LEN
    assert anomaly["frame_end"] == 3 * FRAME64_LEN
    assert anomaly["previous_sequence"] == 1 << 63
    assert anomaly["sequence"] == UINT64_MAX
    assert anomaly["missing"] == (1 << 63) - 2
    assert d2["sequence_audit"]["last_sequence"] == UINT64_MAX
    assert d2["sequence_audit"]["missing_total"] == (1 << 63) - 2

    # 2**64 - 1 -> 0 wraps the u64 modulus: a normal one-step advance.
    d3 = append(client, sid, d2["next_offset"], frame64(0)).json()
    assert d3["sequence_audit"]["anomalies"] == []
    assert d3["sequence_audit"]["last_sequence"] == 0

    # Every wide value is reported exactly by the progress endpoint.
    audit = audit_of(client, sid)
    assert audit["last_sequence"] == 0
    assert audit["suspected_gaps"] == 1
    assert audit["missing_total"] == (1 << 63) - 2


def test_exactly_half_turn_at_64_bit_modulus_is_indeterminate(client):
    register(client)
    sid = make_session(client)["session_id"]

    d = append(client, sid, 0, frame64(0) + frame64(1 << 63)).json()
    (anomaly,) = d["sequence_audit"]["anomalies"]
    # (2**63 - 0) mod 2**64 is exactly half a turn: direction indeterminate,
    # no missing frames inferred.
    assert anomaly["type"] == "indeterminate"
    assert anomaly["missing"] is None
    assert anomaly["sequence"] == 1 << 63
    audit = d["sequence_audit"]
    assert audit["indeterminates"] == 1
    assert audit["missing_total"] == 0
    assert audit["last_sequence"] == 1 << 63


def test_missing_total_accumulates_beyond_signed_64_bit(client):
    register(client)
    sid = make_session(client)["session_id"]

    # Confirming 0, 2**63-1, 0, 2**63-1 in order: two suspected gaps of
    # 2**63-2 missing frames each (one backward jump in between), so the
    # cumulative missing total reaches 2**64 - 4.
    d1 = append(client, sid, 0, frame64(0) + frame64(INT64_MAX)).json()
    assert d1["sequence_audit"]["missing_total"] == INT64_MAX - 1

    d2 = append(client, sid, d1["next_offset"], frame64(0)).json()
    (anomaly,) = d2["sequence_audit"]["anomalies"]
    assert anomaly["type"] == "backward"
    assert anomaly["missing"] is None
    assert d2["sequence_audit"]["missing_total"] == INT64_MAX - 1

    d3 = append(client, sid, d2["next_offset"], frame64(INT64_MAX)).json()
    (anomaly,) = d3["sequence_audit"]["anomalies"]
    assert anomaly["type"] == "suspected_gap"
    assert anomaly["frame_start"] == 3 * FRAME64_LEN
    assert anomaly["frame_end"] == 4 * FRAME64_LEN
    assert anomaly["previous_sequence"] == 0
    assert anomaly["sequence"] == INT64_MAX
    assert anomaly["missing"] == INT64_MAX - 1

    audit = d3["sequence_audit"]
    assert audit["suspected_gaps"] == 2
    assert audit["backwards"] == 1
    assert audit["missing_total"] == 2 * (INT64_MAX - 1) == (1 << 64) - 4
    assert audit["last_sequence"] == INT64_MAX

    # The cumulative total is persisted exactly, not clamped to 2**63 - 1.
    assert audit_of(client, sid)["missing_total"] == (1 << 64) - 4


# ------------------------------------------- commit / replay / failure ----


def test_replay_returns_stored_wide_audit_block_without_double_count(client):
    register(client)
    sid = make_session(client)["session_id"]
    chunk = frame64(0) + frame64(INT64_MAX)  # one suspected gap, missing 2**63-2

    d1 = append(client, sid, 0, chunk).json()
    assert d1["sequence_audit"]["missing_total"] == INT64_MAX - 1

    r2 = append(client, sid, 0, chunk)
    d2 = r2.json()
    assert r2.status_code == 200
    assert d2["replayed"] is True
    assert d2["sequence_audit"] == d1["sequence_audit"]

    audit = audit_of(client, sid)
    assert audit["suspected_gaps"] == 1
    assert audit["missing_total"] == INT64_MAX - 1
    assert audit["last_sequence"] == INT64_MAX


def test_conflict_and_too_large_append_leave_wide_state_untouched(db_path):
    app = create_app(Settings(db_path=db_path, max_decode_bytes=40))
    with TestClient(app) as client:
        register(client)
        sid = make_session(client)["session_id"]

        d1 = append(client, sid, 0, frame64(1 << 63)).json()
        assert d1["sequence_audit"]["last_sequence"] == 1 << 63

        # Same offset, different content: 409, wide audit state unchanged.
        r = append(client, sid, 0, frame64(7))
        assert r.status_code == 409
        assert r.json()["error"]["details"]["reason"] == "content_mismatch"

        # Pending tail + chunk over the decode limit: 413, nothing advances.
        r = append(client, sid, FRAME64_LEN, b"\x00" * 41)
        assert r.status_code == 413

        audit = audit_of(client, sid)
        assert audit["last_sequence"] == 1 << 63
        assert audit["duplicates"] == audit["suspected_gaps"] == 0
        assert audit["backwards"] == audit["indeterminates"] == 0
        assert audit["missing_total"] == 0

        # The session is still usable and the baseline is still 2**63.
        d2 = append(client, sid, FRAME64_LEN, frame64((1 << 63) + 1)).json()
        assert d2["sequence_audit"]["anomalies"] == []
        assert d2["sequence_audit"]["last_sequence"] == (1 << 63) + 1


def test_restart_resumes_wide_audit_state(db_path):
    chunk1 = frame64(0) + frame64(INT64_MAX)  # suspected gap, missing 2**63-2

    with TestClient(create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))) as c:
        register(c)
        sid = make_session(c)["session_id"]
        d1 = append(c, sid, 0, chunk1).json()
        assert d1["sequence_audit"]["missing_total"] == INT64_MAX - 1

    # Simulate a service restart: a brand-new app on the same SQLite file.
    with TestClient(create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))) as c:
        audit = audit_of(c, sid)
        assert audit["bit_width"] == 64
        assert audit["last_sequence"] == INT64_MAX
        assert audit["suspected_gaps"] == 1
        assert audit["missing_total"] == INT64_MAX - 1

        replay = append(c, sid, 0, chunk1).json()
        assert replay["replayed"] is True
        assert replay["sequence_audit"] == d1["sequence_audit"]

        # The persisted baseline (2**63-1) judges the next frame: one normal
        # step onto 2**63, then 2**63 -> 2**63-1 is a backward jump.
        d2 = append(c, sid, replay["next_offset"], frame64(1 << 63)).json()
        assert d2["sequence_audit"]["anomalies"] == []
        assert d2["sequence_audit"]["last_sequence"] == 1 << 63

        d3 = append(c, sid, d2["next_offset"], frame64(INT64_MAX)).json()
        (anomaly,) = d3["sequence_audit"]["anomalies"]
        assert anomaly["type"] == "backward"
        assert anomaly["previous_sequence"] == 1 << 63
        assert d3["sequence_audit"]["backwards"] == 1
        assert d3["sequence_audit"]["missing_total"] == INT64_MAX - 1


def test_wide_audit_state_shared_across_instances(db_path):
    from tests.test_sequence_audit import make_instance

    app_a, client_a = make_instance(db_path)
    app_b, client_b = make_instance(db_path)
    with client_a, client_b:
        register(client_a)
        sid = make_session(client_a)["session_id"]

        d1 = append(client_a, sid, 0, frame64(1 << 63)).json()
        assert d1["sequence_audit"]["last_sequence"] == 1 << 63

        # The peer instance observes the exact wide baseline and its own
        # appends are judged against it.
        audit = audit_of(client_b, sid)
        assert audit["last_sequence"] == 1 << 63

        d2 = append(client_b, sid, d1["next_offset"], frame64((1 << 63) + 2)).json()
        (anomaly,) = d2["sequence_audit"]["anomalies"]
        assert anomaly["type"] == "suspected_gap"
        assert anomaly["missing"] == 1
        assert d2["sequence_audit"]["last_sequence"] == (1 << 63) + 2

        # Both instances read back the same exact cumulative state.
        for client in (client_a, client_b):
            audit = audit_of(client, sid)
            assert audit["last_sequence"] == (1 << 63) + 2
            assert audit["suspected_gaps"] == 1
            assert audit["missing_total"] == 1


# ------------------------------------------------------- existing databases --


# The sessions table as written by the previous release: both wide audit
# columns were SQLite INTEGER, so raw sequences >= 2**63 and cumulative
# missing totals past 2**63 - 1 could not be stored at all.
_AUDIT_ERA_SESSIONS_DDL = """
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
    audit_enabled        INTEGER NOT NULL DEFAULT 0,
    audit_bit_width      INTEGER,
    audit_last_sequence  INTEGER,
    audit_duplicates     INTEGER NOT NULL DEFAULT 0,
    audit_suspected_gaps INTEGER NOT NULL DEFAULT 0,
    audit_backwards      INTEGER NOT NULL DEFAULT 0,
    audit_indeterminates INTEGER NOT NULL DEFAULT 0,
    audit_missing_total  INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def test_audit_era_database_is_rebuilt_and_history_is_exact(tmp_path):
    """A sessions table whose wide audit columns are still INTEGER is
    rebuilt in place with TEXT affinity; historical values read back
    unchanged, the stored last response still replays, and the session
    continues into sequences beyond 2**63 - 1."""
    db_file = tmp_path / "audit-era.db"
    chunk = frame64(INT64_MAX)
    stored_response = {
        "session_id": "old-session",
        "protocol_id": "sensor-line64",
        "version": 1,
        "received_offset": 0,
        "next_offset": FRAME64_LEN,
        "frames": [],
        "discarded": [],
        "tail": {"start": FRAME64_LEN, "end": FRAME64_LEN, "payload_b64": ""},
        "frame_count": 0,
        "frames_total": 1,
        "replayed": False,
        "sequence_audit": {
            "bit_width": 64,
            "last_sequence": INT64_MAX,
            "anomalies": [],
            "duplicates": 1,
            "suspected_gaps": 0,
            "backwards": 0,
            "indeterminates": 0,
            "missing_total": 5,
        },
    }
    conn = sqlite3.connect(str(db_file))
    conn.execute(_AUDIT_ERA_SESSIONS_DDL)
    conn.execute(
        "INSERT INTO sessions "
        "(session_id, protocol_id, version, received_offset, tail_b64, "
        " frames_total, last_chunk_offset, last_chunk_sha256, last_response, "
        " audit_enabled, audit_bit_width, audit_last_sequence, "
        " audit_duplicates, audit_missing_total) "
        "VALUES ('old-session', 'sensor-line64', 1, ?, '', 1, 0, ?, ?, 1, 64, ?, 1, 5)",
        (
            FRAME64_LEN,
            hashlib.sha256(chunk).hexdigest(),
            json.dumps(stored_response),
            INT64_MAX,
        ),
    )
    conn.commit()
    conn.close()

    with TestClient(
        create_app(Settings(db_path=str(db_file), max_decode_bytes=1 << 20))
    ) as c:
        register(c)

        # The wide columns were rebuilt as decimal text; the historical
        # values are exactly the numbers the old database held.
        probe = sqlite3.connect(str(db_file))
        declared = {
            row[1]: row[2].upper()
            for row in probe.execute("PRAGMA table_info(sessions)")
        }
        assert declared["audit_last_sequence"] == "TEXT"
        assert declared["audit_missing_total"] == "TEXT"
        row = probe.execute(
            "SELECT audit_last_sequence, typeof(audit_last_sequence), "
            "       audit_missing_total, typeof(audit_missing_total) "
            "FROM sessions WHERE session_id = 'old-session'"
        ).fetchone()
        assert row == (str(INT64_MAX), "text", "5", "text")
        probe.close()

        # The historical session reads back exactly as before the upgrade.
        progress = c.get("/sessions/old-session").json()
        assert progress["received_offset"] == FRAME64_LEN
        audit = progress["sequence_audit"]
        assert audit["bit_width"] == 64
        assert audit["last_sequence"] == INT64_MAX
        assert audit["duplicates"] == 1
        assert audit["missing_total"] == 5

        # The pre-migration last chunk still replays the stored response.
        replay = append(c, "old-session", 0, chunk).json()
        assert replay["replayed"] is True
        assert replay["sequence_audit"]["last_sequence"] == INT64_MAX
        assert replay["sequence_audit"]["missing_total"] == 5

        # And the session continues past the signed 64-bit boundary: the
        # persisted baseline 2**63-1 judges 2**63 as a normal one-step.
        d = append(c, "old-session", FRAME64_LEN, frame64(1 << 63)).json()
        assert d["sequence_audit"]["anomalies"] == []
        assert d["sequence_audit"]["last_sequence"] == 1 << 63
        assert audit_of(c, "old-session")["last_sequence"] == 1 << 63


# ------------------------------------------- non-audit sessions / decode --


def test_wide_sequences_without_audit_and_in_stateless_decode(client):
    register(client)

    # A session without the audit accepts the same wide sequences; the
    # decoded frame reports them exactly and no audit state appears.
    sid = make_session(client, audit=False)["session_id"]
    d = append(client, sid, 0, frame64(UINT64_MAX)).json()
    assert d["frames"][0]["sequence"] == UINT64_MAX
    assert d["frames"][0]["fields"][0]["raw"] == UINT64_MAX
    assert d["sequence_audit"] is None
    assert client.get(f"/sessions/{sid}").json()["sequence_audit"] is None

    # The stateless decoder is equally exact at the u64 boundary.
    r = client.post(
        "/decode",
        json={"protocol_id": "sensor-line64", "payload_b64": b64(frame64(1 << 63))},
    )
    assert r.status_code == 200, r.text
    frame = r.json()["frames"][0]
    assert frame["sequence"] == 1 << 63
    assert frame["fields"][0]["raw"] == 1 << 63
