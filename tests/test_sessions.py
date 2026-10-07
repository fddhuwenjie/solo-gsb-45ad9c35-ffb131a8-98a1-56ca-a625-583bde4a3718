"""Tests for streaming collection sessions: POST /sessions, /sessions/append, GET /sessions/{id}.

Session semantics under test:

* the registered protocol version is pinned at creation;
* each append prepends the previous pending tail and reuses the existing
  resync decoder, so a frame split across chunks is decoded exactly once;
* only newly confirmed frames/discards are returned with session-wide
  cumulative offsets, plus the new tail and next offset;
* resending the last chunk at the same offset with the same content replays
  the stored response (no duplicate output), even after a service restart;
* same offset + different content or out-of-order/gapped submissions are
  rejected 409 without changing state;
* oversize (tail + chunk) and decoder errors do not advance the offset.
"""
from __future__ import annotations

import base64
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import b64, build_logical, standard_protocol, stuff

SYNC = b"\xaa\x55"


def register(client, **overrides):
    r = client.post("/protocols", json=standard_protocol(**overrides))
    assert r.status_code == 201, r.text
    return r


def make_session(client, protocol_id="sensor-line", version=1):
    r = client.post("/sessions", json={"protocol_id": protocol_id, "version": version})
    assert r.status_code == 201, r.text
    return r.json()


def append(client, sid, offset, chunk):
    return client.post(
        "/sessions/append",
        json={"session_id": sid, "expected_offset": offset, "chunk_b64": b64(chunk)},
    )


# -------------------------------------------------------------- creation -----


def test_create_session_pins_exact_version(client):
    register(client)
    register(client, version=2)

    s = make_session(client, version=1)
    assert s["version"] == 1
    assert s["received_offset"] == 0
    assert s["next_offset"] == 0
    assert s["tail"] == {"start": 0, "end": 0, "payload_b64": ""}
    assert s["frames_total"] == 0

    # A missing exact version is a 404 (no implicit "latest" for sessions).
    r = client.post("/sessions", json={"protocol_id": "sensor-line", "version": 9})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "PROTOCOL_NOT_FOUND"


def test_session_progress_unknown_404(client):
    r = client.get("/sessions/does-not-exist")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "SESSION_NOT_FOUND"

    r = client.post(
        "/sessions/append",
        json={"session_id": "missing", "expected_offset": 0, "chunk_b64": "AA=="},
    )
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "SESSION_NOT_FOUND"


# ----------------------------------------------------------- cross-chunk -----


def test_frame_split_across_chunks_decoded_once_with_session_offsets(client):
    register(client)
    s = make_session(client)
    sid = s["session_id"]

    f1 = SYNC + build_logical(seq=1, addr=3, temp_s16=2345)
    f2 = SYNC + build_logical(seq=2, addr=3, temp_s16=-150)
    stream = b"\x12\x34" + f1 + f2
    cut = len(b"\x12\x34" + f1) + 4  # inside f2

    part1, part2 = stream[:cut], stream[cut:]
    r1 = append(client, sid, 0, part1)
    assert r1.status_code == 200, r1.text
    d1 = r1.json()
    assert d1["received_offset"] == 0
    assert d1["next_offset"] == cut
    assert [(f["start"], f["end"], f["sequence"]) for f in d1["frames"]] == [
        (2, 13, 1)
    ]
    assert [(x["start"], x["end"], x["reason"]) for x in d1["discarded"]] == [
        (0, 2, "noise")
    ]
    assert base64.b64decode(d1["tail"]["payload_b64"]) == f2[:4]
    assert d1["tail"]["start"] == cut - 4
    assert d1["tail"]["end"] == cut
    assert d1["frame_count"] == 1
    assert d1["frames_total"] == 1
    assert d1["replayed"] is False

    r2 = append(client, sid, cut, part2)
    assert r2.status_code == 200, r2.text
    d2 = r2.json()
    # Only the newly completed frame is reported, with session-wide offsets.
    assert [(f["start"], f["end"], f["sequence"]) for f in d2["frames"]] == [
        (cut - 4, cut - 4 + 11, 2)
    ]
    assert d2["discarded"] == []
    assert d2["tail"]["start"] == d2["tail"]["end"] == len(stream)
    assert d2["received_offset"] == cut
    assert d2["next_offset"] == len(stream)
    assert d2["frame_count"] == 1
    assert d2["frames_total"] == 2


def test_sync_header_split_between_chunks(client):
    register(client)
    sid = make_session(client)["session_id"]
    frame = SYNC + build_logical(1, 1, 0)

    # First chunk ends on the first byte of a fresh sync header; that dangling
    # byte must be retained as the pending tail.
    d1 = append(client, sid, 0, frame + b"\xaa").json()
    assert d1["frames"][0]["end"] == len(frame)
    assert base64.b64decode(d1["tail"]["payload_b64"]) == b"\xaa"

    # Second chunk supplies the second sync byte plus a full frame: tail+chunk
    # stitches back into one frame at cumulative offsets.
    rest = b"\x55" + build_logical(2, 1, 0)
    offset = d1["next_offset"]
    d2 = append(client, sid, offset, rest).json()
    assert len(d2["frames"]) == 1
    assert d2["frames"][0]["start"] == offset - 1
    assert d2["frames"][0]["end"] == offset - 1 + 11
    assert d2["frames"][0]["sequence"] == 2


def test_dangling_escape_resolved_by_next_chunk(client):
    register(
        client,
        protocol_id="esc-line",
        escaping={
            "enabled": True,
            "escape_byte": 0x7D,
            "xor_mask": 0x20,
            "escapes_sync": True,
        },
    )
    sid = make_session(client, protocol_id="esc-line")["session_id"]
    wire = SYNC + stuff(build_logical(2, 1, 100))
    cut = len(wire) - 2  # leave a complete frame out of part1 entirely? no: split mid-frame

    part1, part2 = wire[:cut], wire[cut:]
    d1 = append(client, sid, 0, part1).json()
    assert d1["frame_count"] == 0
    assert base64.b64decode(d1["tail"]["payload_b64"]) == part1

    d2 = append(client, sid, cut, part2).json()
    assert d2["frame_count"] == 1
    assert (d2["frames"][0]["start"], d2["frames"][0]["end"]) == (0, len(wire))
    assert d2["frames"][0]["sequence"] == 2
    assert d2["tail"]["start"] == d2["tail"]["end"] == len(wire)


# ---------------------------------------------------------------- retries ----


def test_resend_last_chunk_returns_stored_response_without_duplicates(client):
    register(client)
    sid = make_session(client)["session_id"]
    chunk = SYNC + build_logical(1, 3, 0)

    d1 = append(client, sid, 0, chunk).json()
    assert d1["replayed"] is False

    r2 = append(client, sid, 0, chunk)
    d2 = r2.json()
    assert r2.status_code == 200
    assert d2["replayed"] is True
    assert d2["frames"] == d1["frames"]
    assert d2["discarded"] == d1["discarded"]
    assert d2["tail"] == d1["tail"]
    assert d2["next_offset"] == len(chunk)
    assert d2["frames_total"] == 1  # not double counted

    # After another chunk advances the stream, resending the first (now old)
    # fragment is an out-of-order gap and gets rejected.
    nxt = SYNC + build_logical(2, 3, 0)
    d3 = append(client, sid, len(chunk), nxt).json()
    assert d3["frames_total"] == 2

    r4 = append(client, sid, 0, chunk)
    assert r4.status_code == 409
    assert r4.json()["error"]["code"] == "SESSION_APPEND_CONFLICT"
    assert client.get(f"/sessions/{sid}").json()["frames_total"] == 2


def test_same_offset_different_content_rejected_without_state_change(client):
    register(client)
    sid = make_session(client)["session_id"]
    chunk = SYNC + build_logical(1, 3, 0)

    d1 = append(client, sid, 0, chunk).json()
    assert d1["next_offset"] == len(chunk)

    r = append(client, sid, 0, SYNC + build_logical(2, 3, 0))
    assert r.status_code == 409
    err = r.json()["error"]
    assert err["code"] == "SESSION_APPEND_CONFLICT"
    assert err["details"]["committed_sha256"] != err["details"]["submitted_sha256"]

    progress = client.get(f"/sessions/{sid}").json()
    assert progress["received_offset"] == len(chunk)
    assert progress["frames_total"] == 1

    # The legitimately next chunk is still accepted normally.
    nxt = SYNC + build_logical(3, 3, 0)
    d3 = append(client, sid, len(chunk), nxt).json()
    assert d3["frames"][0]["sequence"] == 3
    assert d3["frames_total"] == 2


def test_out_of_order_gap_is_rejected(client):
    register(client)
    sid = make_session(client)["session_id"]
    chunk = SYNC + build_logical(1, 3, 0)

    append(client, sid, 0, chunk)

    r = append(client, sid, len(chunk) + 5, b"\x01\x02")
    assert r.status_code == 409
    err = r.json()["error"]
    assert err["code"] == "SESSION_APPEND_CONFLICT"
    assert err["details"]["expected_offset"] == len(chunk) + 5
    assert err["details"]["received_offset"] == len(chunk)
    assert client.get(f"/sessions/{sid}").json()["received_offset"] == len(chunk)


# ------------------------------------------------------------- restart -------


def test_restart_resumes_and_replays_stored_response(db_path):
    frame = SYNC + build_logical(1, 3, 2345)
    chunk = b"\x12" + frame + b"\xaa"

    with TestClient(create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))) as c:
        register(c)
        sid = make_session(c)["session_id"]
        d1 = append(c, sid, 0, chunk).json()
        assert d1["next_offset"] == len(chunk)

    # Simulate a service restart: a brand-new app/database handle on the same
    # SQLite file. Progress, tail and last response must all survive.
    with TestClient(create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))) as c:
        progress = c.get(f"/sessions/{sid}").json()
        assert progress["received_offset"] == len(chunk)
        assert progress["next_offset"] == len(chunk)
        assert base64.b64decode(progress["tail"]["payload_b64"]) == b"\xaa"
        assert progress["frames_total"] == 1
        assert progress["last_chunk_offset"] == 0

        replay = append(c, sid, 0, chunk).json()
        assert replay["replayed"] is True
        assert replay["frames"] == d1["frames"]
        assert replay["frames_total"] == 1

        continuation = b"\x55" + build_logical(2, 3, 100)
        d2 = append(c, sid, len(chunk), continuation).json()
        assert d2["frames"][0]["sequence"] == 2
        assert d2["frames"][0]["start"] == len(chunk) - 1
        assert d2["frames_total"] == 2


# ---------------------------------------------------- limits / hard errors ---


def test_tail_plus_chunk_over_limit_rejected_without_advance(db_path):
    with TestClient(create_app(Settings(db_path=db_path, max_decode_bytes=10))) as c:
        register(c)
        sid = make_session(c)["session_id"]
        d1 = append(c, sid, 0, b"\x00" * 8 + b"\xaa").json()
        assert d1["next_offset"] == 9

        r = append(c, sid, 9, b"\x00" * 10)  # tail(1) + chunk(10) = 11 > 10
        assert r.status_code == 413
        assert r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
        assert r.json()["error"]["details"]["size"] == 11
        assert c.get(f"/sessions/{sid}").json()["received_offset"] == 9

        # A chunk small enough to stay within the limit still goes through.
        d2 = append(c, sid, 9, b"\x00").json()
        assert d2["next_offset"] == 10


def test_decoder_hard_error_does_not_advance_offset(client):
    register(client)
    sid = make_session(client)["session_id"]
    # Ambiguous stream: two valid frames end at the same offset -> 422.
    ambiguous = bytes.fromhex("67aa55710aaa550c7845ca08aab4be")

    r = append(client, sid, 0, ambiguous)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "AMBIGUOUS_FRAME"

    progress = client.get(f"/sessions/{sid}").json()
    assert progress["received_offset"] == 0
    assert progress["tail"]["payload_b64"] == ""
    assert progress["last_chunk_offset"] is None

    # The session remains usable: a valid frame at offset 0 is then accepted.
    good = SYNC + build_logical(1, 1, 0)
    d = append(client, sid, 0, good).json()
    assert d["frames"][0]["sequence"] == 1
    assert d["next_offset"] == len(good)


def test_empty_and_invalid_chunk_rejected(client):
    register(client)
    sid = make_session(client)["session_id"]

    r = client.post(
        "/sessions/append",
        json={"session_id": sid, "expected_offset": 0, "chunk_b64": ""},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"

    r = client.post(
        "/sessions/append",
        json={"session_id": sid, "expected_offset": 0, "chunk_b64": "@@@not-b64"},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "INVALID_BASE64"

    assert client.get(f"/sessions/{sid}").json()["received_offset"] == 0


# ------------------------------------------------------------- concurrency ---


def test_concurrent_different_chunks_at_same_offset_one_wins(client):
    register(client)
    sid = make_session(client)["session_id"]

    def submit(payload: bytes) -> int:
        return append(client, sid, 0, payload).status_code

    barrier = threading.Barrier(2)

    def race(payload):
        barrier.wait()
        return submit(payload)

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(race, [b"\x00\x01", b"\x00\x02"]))
    assert sorted(statuses) == [200, 409]
    assert client.get(f"/sessions/{sid}").json()["received_offset"] == 2


def test_concurrent_identical_chunks_produce_no_duplicates(client):
    register(client)
    sid = make_session(client)["session_id"]
    chunk = SYNC + build_logical(1, 3, 0)
    barrier = threading.Barrier(2)

    def race(_):
        barrier.wait()
        return append(client, sid, 0, chunk).json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        bodies = list(pool.map(race, [0, 1]))

    assert sorted(b["replayed"] for b in bodies) == [False, True]
    assert all(b["next_offset"] == len(chunk) for b in bodies)
    assert all(b["frames_total"] == 1 for b in bodies)
    assert client.get(f"/sessions/{sid}").json()["frames_total"] == 1


# -------------------------------------------------------------- progress -----


def test_progress_reports_cumulative_state(client):
    register(client)
    sid = make_session(client)["session_id"]
    chunk = b"\x12\x34" + SYNC + build_logical(1, 3, 0)

    d = append(client, sid, 0, chunk).json()
    p = client.get(f"/sessions/{sid}").json()
    assert p["protocol_id"] == "sensor-line"
    assert p["version"] == 1
    assert p["received_offset"] == p["next_offset"] == len(chunk)
    assert p["frames_total"] == 1
    assert p["last_chunk_offset"] == 0
    assert p["last_chunk_sha256"]
    assert p["tail"]["start"] == d["tail"]["start"]
    assert p["tail"]["end"] == len(chunk)
    assert p["created_at"] and p["updated_at"]
