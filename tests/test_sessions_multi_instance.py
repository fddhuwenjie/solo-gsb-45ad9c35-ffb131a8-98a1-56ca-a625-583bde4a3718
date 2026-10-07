"""Multi-instance session tests: two independent app instances sharing one
SQLite database file, as when the service is deployed with replicas.

The in-process per-session lock cannot serialise appends across instances,
so the commit itself is a database-level compare-and-swap guarded by the
received offset the append was computed from. The race tests force both
instances to read the same pre-commit state (a barrier on the first session
read of each instance) and verify:

* different chunks racing at the same offset: exactly one commits, the
  loser gets 409 SESSION_APPEND_CONFLICT (content_mismatch) and the state
  reflects only the winner;
* identical chunks racing: one commits, the loser replays the stored
  response (replayed=true) and frames are not double counted;
* progress committed by one instance is visible to another live instance,
  and a fresh instance on the same database file (service restart) resumes,
  replays the last chunk and continues without losing or duplicating frames.
"""
from __future__ import annotations

import base64
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import b64, build_logical, standard_protocol

SYNC = b"\xaa\x55"


def make_instance(db_path):
    app = create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))
    return app, TestClient(app)


def register(client, **overrides):
    r = client.post("/protocols", json=standard_protocol(**overrides))
    assert r.status_code == 201, r.text


def make_session(client, protocol_id="sensor-line", version=1):
    r = client.post("/sessions", json={"protocol_id": protocol_id, "version": version})
    assert r.status_code == 201, r.text
    return r.json()["session_id"]


def append(client, sid, offset, chunk):
    return client.post(
        "/sessions/append",
        json={"session_id": sid, "expected_offset": offset, "chunk_b64": b64(chunk)},
    )


def gate_first_session_read(app, barrier):
    """Hold this instance's first session read until both instances read.

    Installed after setup so both racing appends compute from the same
    committed offset; the loser's post-commit re-read passes straight
    through (the gate only trips once per instance).
    """
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


def race_append(client_a, client_b, sid, offset, chunk_a, chunk_b):
    with ThreadPoolExecutor(max_workers=2) as pool:
        future_a = pool.submit(append, client_a, sid, offset, chunk_a)
        future_b = pool.submit(append, client_b, sid, offset, chunk_b)
        return future_a.result(), future_b.result()


# -------------------------------------------------------------- racing -------


def test_two_instances_race_different_chunks_exactly_one_commits(db_path):
    app_a, client_a = make_instance(db_path)
    app_b, client_b = make_instance(db_path)
    with client_a, client_b:
        register(client_a)
        sid = make_session(client_a)

        chunk_a = b"\x00\x01"
        chunk_b = b"\x00\x02"
        barrier = threading.Barrier(2)
        gate_first_session_read(app_a, barrier)
        gate_first_session_read(app_b, barrier)

        resp_a, resp_b = race_append(client_a, client_b, sid, 0, chunk_a, chunk_b)

        # Exactly one commit wins; the loser is a 409 content_mismatch and
        # must not have overwritten the winner's state.
        assert sorted(r.status_code for r in (resp_a, resp_b)) == [200, 409]
        loser = resp_a if resp_a.status_code == 409 else resp_b
        err = loser.json()["error"]
        assert err["code"] == "SESSION_APPEND_CONFLICT"
        assert err["details"]["reason"] == "content_mismatch"

        winner_chunk = chunk_a if resp_a.status_code == 200 else chunk_b
        winner_sha = hashlib.sha256(winner_chunk).hexdigest()

        # Both instances observe the same committed state: only the winner's
        # chunk advanced the session.
        for client in (client_a, client_b):
            progress = client.get(f"/sessions/{sid}").json()
            assert progress["received_offset"] == len(winner_chunk)
            assert progress["next_offset"] == len(winner_chunk)
            assert progress["last_chunk_offset"] == 0
            assert progress["last_chunk_sha256"] == winner_sha

        # The losing instance can still continue the session normally.
        nxt = SYNC + build_logical(1, 3, 0)
        loser_client = client_a if resp_a.status_code == 409 else client_b
        d = append(loser_client, sid, len(winner_chunk), nxt).json()
        assert d["frames_total"] == 1
        assert d["frames"][0]["sequence"] == 1


def test_two_instances_race_identical_chunk_replays_without_duplicates(db_path):
    app_a, client_a = make_instance(db_path)
    app_b, client_b = make_instance(db_path)
    with client_a, client_b:
        register(client_a)
        sid = make_session(client_a)

        chunk = SYNC + build_logical(1, 3, 0)
        barrier = threading.Barrier(2)
        gate_first_session_read(app_a, barrier)
        gate_first_session_read(app_b, barrier)

        resp_a, resp_b = race_append(client_a, client_b, sid, 0, chunk, chunk)

        # Both requests succeed, but exactly one is the real commit; the
        # other is a replay of the stored response and counts nothing twice.
        assert resp_a.status_code == resp_b.status_code == 200
        bodies = [resp_a.json(), resp_b.json()]
        assert sorted(b["replayed"] for b in bodies) == [False, True]
        assert all(b["next_offset"] == len(chunk) for b in bodies)
        assert all(b["frames_total"] == 1 for b in bodies)
        assert all(b["frames"] == bodies[0]["frames"] for b in bodies)

        for client in (client_a, client_b):
            progress = client.get(f"/sessions/{sid}").json()
            assert progress["received_offset"] == len(chunk)
            assert progress["frames_total"] == 1

        # A later resend through the other instance still replays.
        again = append(client_b, sid, 0, chunk).json()
        assert again["replayed"] is True
        assert again["frames_total"] == 1
        assert client_a.get(f"/sessions/{sid}").json()["frames_total"] == 1


# -------------------------------------------------- sharing / restart --------


def test_two_live_instances_alternate_appends(db_path):
    app_a, client_a = make_instance(db_path)
    app_b, client_b = make_instance(db_path)
    with client_a, client_b:
        register(client_a)
        sid = make_session(client_a)

        chunk1 = SYNC + build_logical(1, 3, 0)
        d1 = append(client_a, sid, 0, chunk1).json()
        assert d1["frames_total"] == 1

        # The second instance sees the first instance's committed offset and
        # continues the stream; the frame is produced exactly once overall.
        chunk2 = SYNC + build_logical(2, 3, 0)
        d2 = append(client_b, sid, len(chunk1), chunk2).json()
        assert d2["received_offset"] == len(chunk1)
        assert d2["frames"][0]["sequence"] == 2
        assert d2["frames_total"] == 2

        progress = client_a.get(f"/sessions/{sid}").json()
        assert progress["received_offset"] == len(chunk1) + len(chunk2)
        assert progress["frames_total"] == 2
        assert progress["last_chunk_offset"] == len(chunk1)


def test_fresh_instance_resumes_progress_and_replays(db_path):
    frame = SYNC + build_logical(1, 3, 2345)
    chunk = b"\x12" + frame + b"\xaa"

    app_a, client_a = make_instance(db_path)
    with client_a:
        register(client_a)
        sid = make_session(client_a)
        d1 = append(client_a, sid, 0, chunk).json()
        assert d1["next_offset"] == len(chunk)

    # Simulate a service restart (or a peer replica): a brand-new app and
    # database handle on the same SQLite file. Progress, tail and the last
    # response must all be visible.
    app_b, client_b = make_instance(db_path)
    with client_b:
        progress = client_b.get(f"/sessions/{sid}").json()
        assert progress["received_offset"] == len(chunk)
        assert progress["next_offset"] == len(chunk)
        assert base64.b64decode(progress["tail"]["payload_b64"]) == b"\xaa"
        assert progress["frames_total"] == 1
        assert progress["last_chunk_offset"] == 0

        replay = append(client_b, sid, 0, chunk).json()
        assert replay["replayed"] is True
        assert replay["frames"] == d1["frames"]
        assert replay["frames_total"] == 1

        continuation = b"\x55" + build_logical(2, 3, 100)
        d2 = append(client_b, sid, len(chunk), continuation).json()
        assert d2["frames"][0]["sequence"] == 2
        assert d2["frames"][0]["start"] == len(chunk) - 1
        assert d2["frames_total"] == 2

    # A further restart still observes the final committed state.
    app_c, client_c = make_instance(db_path)
    with client_c:
        progress = client_c.get(f"/sessions/{sid}").json()
        assert progress["received_offset"] == len(chunk) + len(continuation)
        assert progress["frames_total"] == 2
        assert progress["last_chunk_offset"] == len(chunk)
