"""Targeted tests for upgrading an old (INTEGER wide-column) sessions table
when two service instances start against the same SQLite database file.

The upgrade adds the audit columns in place and rebuilds the sessions table
to give ``audit_last_sequence`` / ``audit_missing_total`` TEXT affinity, all
as one cross-process write transaction (``BEGIN IMMEDIATE``). Under test:

* two OS processes opening the same old database at the same moment both
  start cleanly: one performs the upgrade while the other waits on the
  database write lock, then re-checks the structure and has nothing to do;
* a deterministic in-process version proves the late instance blocks until
  the upgrade commits, re-judges the column types afterwards and skips the
  rebuild (no ADD COLUMN / staging-table statements of its own);
* a failure in the middle of the rebuild rolls the transaction back: the
  original ``sessions`` table, its INTEGER columns and every row survive,
  no staging table is left behind, and the next start retries to completion;
* after the upgrade both instances query the old session, replay its last
  shard and continue appending, including audit values past SQLite's signed
  64-bit INTEGER range.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import sqlite3
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import db as dbmod
from app.config import Settings
from app.main import create_app
from tests.conftest import b64
from tests.test_sequence_audit_wide import (
    _AUDIT_ERA_SESSIONS_DDL,
    FRAME64_LEN,
    INT64_MAX,
    UINT64_MAX,
    frame64,
    u64_protocol,
)

# Spawned child processes re-import this module (and the app package).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# --------------------------------------------------------------- helpers ----


def _seed_audit_era_database(path: str, *, rows: int = 1) -> None:
    """Create a database written by the previous release.

    The sessions table has both wide audit columns as SQLite INTEGER and is
    populated with one audit-enabled session (baseline 2**63 - 1) whose last
    shard can be replayed.
    """
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_AUDIT_ERA_SESSIONS_DDL)
    _insert_audit_era_rows(conn, rows)
    conn.commit()
    conn.close()


def _insert_audit_era_rows(conn: sqlite3.Connection, rows: int) -> None:
    for i in range(rows):
        chunk = frame64(INT64_MAX)
        stored_response = {
            "session_id": f"old-session-{i}",
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
        conn.execute(
            "INSERT INTO sessions "
            "(session_id, protocol_id, version, received_offset, tail_b64, "
            " frames_total, last_chunk_offset, last_chunk_sha256, last_response, "
            " audit_enabled, audit_bit_width, audit_last_sequence, "
            " audit_duplicates, audit_missing_total) "
            f"VALUES ('old-session-{i}', 'sensor-line64', 1, ?, '', 1, 0, ?, ?, "
            "1, 64, ?, 1, 5)",
            (
                FRAME64_LEN,
                hashlib.sha256(chunk).hexdigest(),
                json.dumps(stored_response),
                INT64_MAX,
            ),
        )


_PRE_AUDIT_SESSIONS_DDL = """
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


def _seed_pre_audit_database(path: str, *, rows: int = 1) -> None:
    """Create a database from the release before any audit column existed."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_PRE_AUDIT_SESSIONS_DDL)
    for i in range(rows):
        conn.execute(
            "INSERT INTO sessions "
            "(session_id, protocol_id, version, received_offset, tail_b64, "
            " frames_total, last_response) "
            f"VALUES ('pre-session-{i}', 'sensor-line64', 1, 0, '', 0, '')"
        )
    conn.commit()
    conn.close()


def _wide_column_types(path: str) -> dict[str, str]:
    probe = sqlite3.connect(path)
    try:
        return {
            row[1]: (row[2] or "").upper()
            for row in probe.execute("PRAGMA table_info(sessions)")
            if row[1] in ("audit_last_sequence", "audit_missing_total")
        }
    finally:
        probe.close()


def _table_names(path: str) -> list[str]:
    probe = sqlite3.connect(path)
    try:
        return sorted(
            row[0]
            for row in probe.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        )
    finally:
        probe.close()


def make_instance(db_path):
    app = create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))
    return app, TestClient(app)


def append(client, sid, offset, chunk):
    return client.post(
        "/sessions/append",
        json={"session_id": sid, "expected_offset": offset, "chunk_b64": b64(chunk)},
    )


# --------------------------------------------- true cross-process upgrade ----


def _concurrent_init_worker(db_path, barrier, errors, delay_mode):
    """Spawn-process entry point: wait for the peer, then initialise the
    shared database exactly like a service instance does at startup.

    ``delay_mode`` opens the old build's race window deterministically: the
    connection pauses after every ``PRAGMA table_info(sessions)`` read, so
    both processes read the old structure before either one acquires the
    write lock. With the fixed migration the second process waits on the
    lock and re-checks the structure; without the transaction it re-issues
    an ALTER / staging-table statement that already committed and crashes.
    """
    import time

    if delay_mode:
        real_connect = dbmod.sqlite3.connect

        class RacedConnection(sqlite3.Connection):
            def execute(self, sql, *args):
                result = super().execute(sql, *args)
                if (
                    delay_mode == "after_type_check"
                    and isinstance(sql, str)
                    and sql.strip().upper() == "PRAGMA TABLE_INFO(SESSIONS)"
                ):
                    time.sleep(1.5)
                return result

        def raced_connect(*args, **kwargs):
            kwargs.setdefault("factory", RacedConnection)
            return real_connect(*args, **kwargs)

        dbmod.sqlite3.connect = raced_connect

    try:
        barrier.wait(30)
        dbmod.init_db(db_path)
    except BaseException as exc:  # noqa: BLE001 - reported back to the parent
        errors.put(f"{type(exc).__name__}: {exc}")


def _run_two_processes_upgrading(db_path: str, delay_mode: str | None) -> list[str]:
    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    errors = ctx.Queue()
    procs = [
        ctx.Process(
            target=_concurrent_init_worker,
            args=(db_path, barrier, errors, delay_mode),
        )
        for _ in range(2)
    ]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(60)
    failures = []
    while not errors.empty():
        failures.append(errors.get())
    assert [p.exitcode for p in procs] == [0, 0], failures
    return failures


def test_two_processes_upgrade_audit_era_database_simultaneously(tmp_path):
    db_file = tmp_path / "shared-audit-era.db"
    # Several historical rows verify the staging copy converts every row,
    # not just the first, to exact decimal text.
    _seed_audit_era_database(str(db_file), rows=200)

    failures = _run_two_processes_upgrading(str(db_file), "after_type_check")
    assert failures == []

    # Exactly one sessions table, rebuilt with TEXT wide columns; the other
    # process must not have left a staging table behind.
    assert _table_names(str(db_file)) == ["decode_cache", "protocols", "sessions"]
    assert _wide_column_types(str(db_file)) == {
        "audit_last_sequence": "TEXT",
        "audit_missing_total": "TEXT",
    }
    probe = sqlite3.connect(str(db_file))
    try:
        count = probe.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        row = probe.execute(
            "SELECT audit_last_sequence, typeof(audit_last_sequence), "
            "       audit_missing_total, typeof(audit_missing_total), "
            "       received_offset, frames_total "
            "FROM sessions WHERE session_id = 'old-session-0'"
        ).fetchone()
    finally:
        probe.close()
    assert count == 200
    assert row == (str(INT64_MAX), "text", "5", "text", FRAME64_LEN, 1)


def test_two_processes_add_audit_columns_simultaneously(tmp_path):
    """The column-add half of the upgrade races the same way: both instances
    read the column-less structure before adding columns."""
    db_file = tmp_path / "shared-pre-audit.db"
    _seed_pre_audit_database(str(db_file), rows=2)

    failures = _run_two_processes_upgrading(str(db_file), "after_type_check")
    assert failures == []

    probe = sqlite3.connect(str(db_file))
    try:
        declared = {
            row[1]: (row[2] or "").upper()
            for row in probe.execute("PRAGMA table_info(sessions)")
        }
        assert declared["audit_last_sequence"] == "TEXT"
        assert declared["audit_missing_total"] == "TEXT"
        assert declared["audit_enabled"] == "INTEGER"
        rows = probe.execute(
            "SELECT session_id, audit_enabled, audit_missing_total "
            "FROM sessions ORDER BY session_id"
        ).fetchall()
    finally:
        probe.close()
    assert rows == [
        ("pre-session-0", 0, "0"),
        ("pre-session-1", 0, "0"),
    ]


# ------------------------------------ late instance waits and re-judges ------


class _InstrumentedConnection(sqlite3.Connection):
    """Connection recording schema-changing statements issued through it."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.schema_statements: list[str] = []

    def execute(self, sql, *args):
        if isinstance(sql, str):
            upper = sql.strip().upper()
            if (
                upper.startswith("ALTER TABLE SESSIONS ADD")
                or "SESSIONS_WIDE_MIGRATION" in upper
                or upper == "DROP TABLE SESSIONS"
            ):
                self.schema_statements.append(upper)
        return super().execute(sql, *args)


def test_late_instance_waits_then_rechecks_and_skips_rebuild(tmp_path, monkeypatch):
    db_file = str(tmp_path / "wait-and-recheck.db")
    _seed_audit_era_database(db_file)

    # The "first" instance takes the write lock, performs the full upgrade
    # and deliberately keeps the transaction open (and the lock held) until
    # the second instance is known to be waiting on it. The connection is
    # handed to the holder thread, so disable the same-thread restriction.
    holder = sqlite3.connect(db_file, timeout=30, check_same_thread=False)
    holder.isolation_level = None
    holder.execute("BEGIN IMMEDIATE")
    dbmod._migrate_sessions_locked(holder)

    release = threading.Event()
    committed = threading.Event()

    def hold_lock():
        release.wait(10)
        holder.execute("COMMIT")
        holder.close()
        committed.set()

    holder_thread = threading.Thread(target=hold_lock)
    holder_thread.start()

    # Route only the second instance's connection through the instrumented
    # factory so its own schema statements can be audited.
    real_connect = dbmod.sqlite3.connect
    waiter_conn: list[_InstrumentedConnection] = []

    def instrumented_connect(*args, **kwargs):
        kwargs.setdefault("factory", _InstrumentedConnection)
        conn = real_connect(*args, **kwargs)
        waiter_conn.append(conn)
        return conn

    monkeypatch.setattr(dbmod.sqlite3, "connect", instrumented_connect)

    finished = threading.Event()

    def late_start():
        dbmod._initialize_database(db_file)
        finished.set()

    waiter_thread = threading.Thread(target=late_start)
    waiter_thread.start()

    # While the upgrade lock is held the late instance must stay blocked;
    # its busy_timeout (30s) is what makes it wait rather than fail startup.
    waiter_thread.join(2)
    assert not finished.is_set()

    release.set()
    holder_thread.join(10)
    committed.wait(10)
    waiter_thread.join(40)
    assert finished.is_set(), "late instance did not finish after the lock released"

    # It acquired the lock, re-read the column types, saw TEXT and skipped
    # both the column adds and the staging-table rebuild entirely.
    assert waiter_conn and waiter_conn[0].schema_statements == []

    assert _wide_column_types(db_file) == {
        "audit_last_sequence": "TEXT",
        "audit_missing_total": "TEXT",
    }


# --------------------------------------------- failure rolls the upgrade ----


class _FailAtDropConnection(sqlite3.Connection):
    def execute(self, sql, *args):
        # Fail after the staging copy, immediately before the original table
        # is dropped — the point of greatest danger for historical sessions.
        if isinstance(sql, str) and sql.strip().upper() == "DROP TABLE SESSIONS":
            raise sqlite3.OperationalError("injected failure mid migration")
        return super().execute(sql, *args)


def test_failed_upgrade_keeps_original_table_and_retries(tmp_path, monkeypatch):
    db_file = str(tmp_path / "rollback.db")
    _seed_audit_era_database(db_file)

    real_connect = dbmod.sqlite3.connect
    monkeypatch.setattr(
        dbmod.sqlite3,
        "connect",
        lambda *args, **kwargs: real_connect(
            *args, factory=_FailAtDropConnection, **kwargs
        ),
    )

    with pytest.raises(sqlite3.OperationalError, match="injected"):
        dbmod.init_db(db_file)
    monkeypatch.undo()

    # The whole initialisation transaction rolled back: the database looks
    # exactly as it did before the start was attempted — original columns
    # still INTEGER, all rows still present, no base tables or staging table
    # ever visible.
    assert _wide_column_types(db_file) == {
        "audit_last_sequence": "INTEGER",
        "audit_missing_total": "INTEGER",
    }
    assert _table_names(db_file) == ["sessions"]
    probe = sqlite3.connect(db_file)
    try:
        row = probe.execute(
            "SELECT audit_last_sequence, audit_missing_total, received_offset "
            "FROM sessions WHERE session_id = 'old-session-0'"
        ).fetchone()
    finally:
        probe.close()
    assert row == (INT64_MAX, 5, FRAME64_LEN)

    # A later start retries the same upgrade and completes it; the historical
    # values come through as exact decimal text.
    dbmod.init_db(db_file)
    assert _table_names(db_file) == ["decode_cache", "protocols", "sessions"]
    assert _wide_column_types(db_file) == {
        "audit_last_sequence": "TEXT",
        "audit_missing_total": "TEXT",
    }
    probe = sqlite3.connect(db_file)
    try:
        row = probe.execute(
            "SELECT audit_last_sequence, typeof(audit_last_sequence), "
            "       audit_missing_total, typeof(audit_missing_total) "
            "FROM sessions WHERE session_id = 'old-session-0'"
        ).fetchone()
    finally:
        probe.close()
    assert row == (str(INT64_MAX), "text", "5", "text")


# ----------------- both instances use the upgraded session afterwards -------


def test_both_instances_query_replay_and_continue_after_upgrade(tmp_path):
    db_file = str(tmp_path / "after-upgrade.db")
    _seed_audit_era_database(db_file)

    # Simulate the simultaneous first start; then both apps open the already
    # upgraded file as they would after a rolling restart.
    dbmod.init_db(db_file)
    app_a, client_a = make_instance(db_file)
    app_b, client_b = make_instance(db_file)
    assert app_a is not app_b
    with client_a, client_b:
        # Protocol rows live in the same shared file; registration on one
        # instance is immediately visible to the other.
        r = client_a.post("/protocols", json=u64_protocol())
        assert r.status_code == 201, r.text

        sid = "old-session-0"

        # Both instances read the historical session with its exact audit
        # values (baseline 2**63 - 1, cumulative missing 5).
        for client in (client_a, client_b):
            progress = client.get(f"/sessions/{sid}").json()
            assert progress["received_offset"] == FRAME64_LEN
            assert progress["frames_total"] == 1
            audit = progress["sequence_audit"]
            assert audit["bit_width"] == 64
            assert audit["last_sequence"] == INT64_MAX
            assert audit["duplicates"] == 1
            assert audit["missing_total"] == 5

        # The pre-upgrade last shard replays its stored response verbatim on
        # the peer instance, without re-decoding or double counting.
        chunk0 = frame64(INT64_MAX)
        replay = append(client_b, sid, 0, chunk0).json()
        assert replay["replayed"] is True
        assert replay["sequence_audit"]["last_sequence"] == INT64_MAX
        assert replay["sequence_audit"]["missing_total"] == 5
        assert replay["frames_total"] == 1

        # Continue the stream across instances. 2**63-1 -> 2**63 is a normal
        # one-step advance onto a value SQLite INTEGER cannot hold.
        d1 = append(client_a, sid, FRAME64_LEN, frame64(1 << 63)).json()
        assert d1["sequence_audit"]["anomalies"] == []
        assert d1["sequence_audit"]["last_sequence"] == 1 << 63

        # 2**63 -> 2**64-1 is a suspected gap of 2**63-2 frames, which pushes
        # the cumulative missing total past the signed 64-bit maximum; it
        # must remain exact and be readable from either instance.
        wide_missing = 5 + ((1 << 63) - 2)
        assert wide_missing > INT64_MAX
        d2 = append(client_b, sid, d1["next_offset"], frame64(UINT64_MAX)).json()
        (anomaly,) = d2["sequence_audit"]["anomalies"]
        assert anomaly["type"] == "suspected_gap"
        assert anomaly["missing"] == (1 << 63) - 2
        assert d2["sequence_audit"]["last_sequence"] == UINT64_MAX
        assert d2["sequence_audit"]["missing_total"] == wide_missing

        for client in (client_a, client_b):
            audit = client.get(f"/sessions/{sid}").json()["sequence_audit"]
            assert audit["last_sequence"] == UINT64_MAX
            assert audit["missing_total"] == wide_missing

        # The last shard now replays on the other instance with the wide
        # values intact, and another append keeps building on them.
        again = append(client_a, sid, d1["next_offset"], frame64(UINT64_MAX)).json()
        assert again["replayed"] is True
        assert again["sequence_audit"]["missing_total"] == wide_missing

        progress = client_b.get(f"/sessions/{sid}").json()
        assert progress["received_offset"] == 3 * FRAME64_LEN
        assert progress["frames_total"] == 3
