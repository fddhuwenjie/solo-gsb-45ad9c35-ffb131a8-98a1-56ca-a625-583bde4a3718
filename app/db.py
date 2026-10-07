"""SQLite storage for protocol declarations and idempotent decode results."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .audit import MIN_BIT_WIDTH, sequence_bit_width
from .models import DecodeResponse, ProtocolDefinition

# Every column of the sessions table, in declaration order. Used by the
# in-place rebuild that converts pre-existing databases to the wide audit
# column format (see _migrate_sessions_locked).
_SESSION_COLUMNS = (
    "session_id",
    "protocol_id",
    "version",
    "received_offset",
    "tail_b64",
    "frames_total",
    "last_chunk_offset",
    "last_chunk_sha256",
    "last_response",
    "audit_enabled",
    "audit_bit_width",
    "audit_last_sequence",
    "audit_duplicates",
    "audit_suspected_gaps",
    "audit_backwards",
    "audit_indeterminates",
    "audit_missing_total",
    "created_at",
    "updated_at",
)

# Audit values that do not fit SQLite's signed 64-bit INTEGER:
# audit_last_sequence can be any raw u64 sequence (up to 2**64 - 1) and
# audit_missing_total accumulates inferred gaps without bound. Both are
# persisted as decimal text, which is lossless at any magnitude.
_WIDE_AUDIT_COLUMNS = ("audit_last_sequence", "audit_missing_total")


def _sessions_table_sql(table: str) -> str:
    return f"""
CREATE TABLE IF NOT EXISTS {table} (
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
    audit_last_sequence  TEXT,
    audit_duplicates     INTEGER NOT NULL DEFAULT 0,
    audit_suspected_gaps INTEGER NOT NULL DEFAULT 0,
    audit_backwards      INTEGER NOT NULL DEFAULT 0,
    audit_indeterminates INTEGER NOT NULL DEFAULT 0,
    audit_missing_total  TEXT NOT NULL DEFAULT '0',
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


# Base schema statements, executed individually inside the startup write
# transaction (executescript would force its own COMMIT). Each uses
# IF NOT EXISTS, so a later starter that waited on the lock applies them as
# no-ops before re-checking the sessions structure.
_SCHEMA_STATEMENTS = (
    """
CREATE TABLE IF NOT EXISTS protocols (
    protocol_id   TEXT NOT NULL,
    version       INTEGER NOT NULL,
    definition    TEXT NOT NULL,
    definition_sha256 TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (protocol_id, version)
)
""",
    """
CREATE TABLE IF NOT EXISTS decode_cache (
    protocol_id     TEXT NOT NULL,
    version         INTEGER NOT NULL,
    input_sha256    TEXT NOT NULL,
    result          TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (protocol_id, version, input_sha256)
)
""",
    _sessions_table_sql("sessions"),
)

# Sequence-audit columns were added after the initial release. Existing
# database files keep their old sessions table (CREATE TABLE IF NOT EXISTS
# never alters it), so add any missing column in place; sessions created
# before the upgrade simply have the audit disabled. The two wide columns
# are added as TEXT from the start (see _WIDE_AUDIT_COLUMNS).
_SESSION_AUDIT_COLUMNS = {
    "audit_enabled": "INTEGER NOT NULL DEFAULT 0",
    "audit_bit_width": "INTEGER",
    "audit_last_sequence": "TEXT",
    "audit_duplicates": "INTEGER NOT NULL DEFAULT 0",
    "audit_suspected_gaps": "INTEGER NOT NULL DEFAULT 0",
    "audit_backwards": "INTEGER NOT NULL DEFAULT 0",
    "audit_indeterminates": "INTEGER NOT NULL DEFAULT 0",
    "audit_missing_total": "TEXT NOT NULL DEFAULT '0'",
}

# How long a concurrent starter waits on the database write lock before
# SQLite raises "database is locked". The first instance holds that lock for
# the whole session upgrade; every other instance waits here instead of
# racing on the schema, then re-checks the structure once it acquires it.
_MIGRATION_BUSY_TIMEOUT_MS = 30_000

# Switching the journal mode to WAL on a database another process is
# creating in parallel can return "database is locked" without invoking the
# busy handler (the file header is still being initialised). Retry briefly;
# once the database exists in WAL mode the pragma is a read-only no-op.
_WAL_SETTLE_RETRIES = 30
_WAL_SETTLE_DELAY_S = 0.2

_init_lock = threading.Lock()
_initialized: set[str] = set()


def _connect(db_path: str, *, busy_timeout_ms: int = 10_000) -> sqlite3.Connection:
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=busy_timeout_ms / 1000, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # busy_timeout must be in effect before journal_mode=WAL: switching the
    # journal mode needs the write lock, and a concurrent initialiser would
    # otherwise fail connection setup with "database is locked".
    conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    _enable_wal(conn, db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _enable_wal(conn: sqlite3.Connection, db_path: str) -> None:
    if db_path == ":memory:":
        return
    for attempt in range(_WAL_SETTLE_RETRIES):
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as exc:
            # Only the cross-process "file still being created" lock is
            # retried; anything else propagates from connection setup.
            if "locked" not in str(exc).lower():
                raise
            time.sleep(_WAL_SETTLE_DELAY_S)
    conn.execute("PRAGMA journal_mode=WAL")


def init_db(db_path: str) -> None:
    with _init_lock:
        if db_path in _initialized:
            return
        _initialize_database(db_path)
        _initialized.add(db_path)


def _initialize_database(db_path: str) -> None:
    """Create the base schema and upgrade the sessions table on one file.

    Runs without the process lock so it also describes what every OS process
    does independently when several instances share one SQLite file.
    """
    conn = _connect(db_path, busy_timeout_ms=_MIGRATION_BUSY_TIMEOUT_MS)
    # Autocommit mode with explicit transaction boundaries: the whole
    # initialisation is one write transaction, so Python's sqlite3 layer
    # cannot split it into separately locked statements.
    conn.isolation_level = None
    try:
        # BEGIN IMMEDIATE honours busy_timeout: for a brand-new database one
        # process creates the schema while the other waits and then finds
        # every table already present; for an old database one process runs
        # the session upgrade and the other re-checks an already-new schema.
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in _SCHEMA_STATEMENTS:
                conn.execute(statement)
            _migrate_sessions_locked(conn)
        except Exception:
            # Roll back before propagating; ignore a rollback error (e.g. the
            # connection is already unusable) so the original failure surfaces.
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        conn.execute("COMMIT")
    finally:
        conn.close()


def _migrate_sessions_locked(conn: sqlite3.Connection) -> None:
    """Add missing audit columns and rebuild for wide columns, one upgrade.

    The caller already holds the cross-process write lock
    (``BEGIN IMMEDIATE``) inside the single startup transaction. With that
    lock held, two service instances starting against the same old database
    file cannot interleave: one performs the upgrade while the other blocks
    (up to ``_MIGRATION_BUSY_TIMEOUT_MS``) and, once it acquires the lock,
    re-reads the structure and finds nothing left to do. The enclosing
    transaction either commits the complete new table or rolls every
    statement back — a failed upgrade leaves the original ``sessions`` table
    and its rows in place, so the next start retries the upgrade from
    scratch.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
    for name, ddl in _SESSION_AUDIT_COLUMNS.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE sessions ADD COLUMN {name} {ddl}")
    _rebuild_sessions_for_wide_audit(conn)


def _rebuild_sessions_for_wide_audit(conn: sqlite3.Connection) -> None:
    """Rebuild the sessions table when the wide audit columns are not TEXT.

    Databases written while ``audit_last_sequence`` / ``audit_missing_total``
    were INTEGER columns cannot hold raw u64 sequences or cumulative missing
    counts past 2**63 - 1 (SQLite INTEGER is signed 64-bit, and a numeric
    string that overflows it would be stored as a lossy REAL). Rebuilding
    the table with TEXT-affinity columns converts every stored integer to
    its exact decimal text on copy, so historical sessions read back with
    the same values they had before the migration.

    Every statement here (including DROP/RENAME) runs inside the caller's
    migration transaction. A failure before the final RENAME is simply
    rolled back: the original ``sessions`` table keeps its rows and the
    staging table vanishes, so a retry on the next start can begin cleanly.
    """
    declared = {
        row[1]: (row[2] or "").upper()
        for row in conn.execute("PRAGMA table_info(sessions)")
    }
    if all(declared.get(name) == "TEXT" for name in _WIDE_AUDIT_COLUMNS):
        return
    cols = ", ".join(_SESSION_COLUMNS)
    # No other upgrade can be in flight on this file (the migration
    # transaction holds the write lock), but a staging table from an upgrade
    # of a much older build could survive a crash; drop it inside this
    # transaction before rebuilding.
    conn.execute("DROP TABLE IF EXISTS sessions_wide_migration")
    conn.execute(_sessions_table_sql("sessions_wide_migration"))
    conn.execute(
        f"INSERT INTO sessions_wide_migration ({cols}) SELECT {cols} FROM sessions"
    )
    conn.execute("DROP TABLE sessions")
    conn.execute("ALTER TABLE sessions_wide_migration RENAME TO sessions")


def _encode_wide(value: int | None) -> str | None:
    """Persist an arbitrary-precision audit integer as exact decimal text."""
    return None if value is None else str(value)


def _decode_wide(value: Any) -> int | None:
    """Decode a wide audit value read from the database.

    Current rows store decimal text; rows written before the wide format
    existed (only possible for values below 2**63) hold plain integers.
    Both decode to the same Python int.
    """
    return None if value is None else int(value)


class Database:
    def __init__(self, db_path: str) -> None:
        init_db(db_path)
        self._db_path = db_path
        self._local = threading.local()

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = _connect(self._db_path)
            self._local.conn = conn
        return conn

    # ----- protocols -------------------------------------------------------

    def upsert_protocol(self, proto: ProtocolDefinition, definition_sha: str) -> None:
        payload = proto.model_dump_json(by_alias=True)
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO protocols "
                "(protocol_id, version, definition, definition_sha256) VALUES (?, ?, ?, ?)",
                (proto.protocol_id, proto.version, payload, definition_sha),
            )

    def get_protocol_row(self, protocol_id: str, version: int | None) -> sqlite3.Row | None:
        cur = self.conn.cursor()
        if version is not None:
            cur.execute(
                "SELECT * FROM protocols WHERE protocol_id = ? AND version = ?",
                (protocol_id, version),
            )
            return cur.fetchone()
        cur.execute(
            "SELECT * FROM protocols WHERE protocol_id = ? ORDER BY version DESC LIMIT 1",
            (protocol_id,),
        )
        return cur.fetchone()

    @staticmethod
    def row_to_protocol(row: sqlite3.Row) -> ProtocolDefinition:
        return ProtocolDefinition.model_validate(json.loads(row["definition"]))

    def find_protocol(self, protocol_id: str, version: int | None) -> tuple[ProtocolDefinition, int] | None:
        row = self.get_protocol_row(protocol_id, version)
        if row is None:
            return None
        return self.row_to_protocol(row), row["version"]

    def list_protocols(self) -> list[dict[str, Any]]:
        cur = self.conn.execute(
            "SELECT protocol_id, version, definition_sha256, created_at "
            "FROM protocols ORDER BY protocol_id, version"
        )
        return [dict(r) for r in cur.fetchall()]

    # ----- decode cache ----------------------------------------------------

    def get_cached(self, protocol_id: str, version: int, input_sha: str) -> dict | None:
        cur = self.conn.execute(
            "SELECT result FROM decode_cache WHERE protocol_id = ? AND version = ? AND input_sha256 = ?",
            (protocol_id, version, input_sha),
        )
        row = cur.fetchone()
        return json.loads(row["result"]) if row else None

    def put_cached(
        self, protocol_id: str, version: int, input_sha: str, result: DecodeResponse
    ) -> None:
        payload = result.model_dump_json()
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO decode_cache "
                "(protocol_id, version, input_sha256, result) VALUES (?, ?, ?, ?)",
                (protocol_id, version, input_sha, payload),
            )

    # ----- collection sessions ---------------------------------------------

    def create_session(
        self,
        session_id: str,
        protocol_id: str,
        version: int,
        *,
        audit_enabled: bool = False,
        audit_bit_width: int | None = None,
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO sessions "
                "(session_id, protocol_id, version, received_offset, tail_b64, "
                " frames_total, last_chunk_offset, last_chunk_sha256, last_response, "
                " audit_enabled, audit_bit_width) "
                "VALUES (?, ?, ?, 0, '', 0, NULL, NULL, '', ?, ?)",
                (session_id, protocol_id, version, int(audit_enabled), audit_bit_width),
            )

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        cur = self.conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        session = dict(row)
        # Wide audit values persist as decimal text; hand callers plain
        # Python ints so comparisons and JSON responses stay exact at any
        # magnitude (see _WIDE_AUDIT_COLUMNS).
        session["audit_last_sequence"] = _decode_wide(session["audit_last_sequence"])
        session["audit_missing_total"] = _decode_wide(session["audit_missing_total"])
        return session

    def get_session_export(self, session_id: str) -> dict[str, Any] | None:
        """Read one session plus its protocol definition digest atomically.

        The single joined SELECT is one statement, hence one snapshot: all
        session columns and the protocol's ``definition_sha256`` come from the
        same committed point in time, so an exported checkpoint can never mix
        an append state with a different commit's protocol metadata. Wide
        audit values are decoded to exact Python ints like get_session().
        """
        cur = self.conn.execute(
            "SELECT s.*, p.definition_sha256 AS protocol_definition_sha256 "
            "FROM sessions AS s "
            "JOIN protocols AS p "
            "  ON p.protocol_id = s.protocol_id AND p.version = s.version "
            "WHERE s.session_id = ?",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        session = dict(row)
        session["audit_last_sequence"] = _decode_wide(session["audit_last_sequence"])
        session["audit_missing_total"] = _decode_wide(session["audit_missing_total"])
        return session

    def import_session_checkpoint(
        self,
        *,
        session_id: str,
        protocol_id: str,
        version: int,
        definition_sha: str,
        received_offset: int,
        tail_b64: str,
        frames_total: int,
        last_chunk_offset: int | None,
        last_chunk_sha: str | None,
        last_response_json: str,
        audit_enabled: bool,
        audit_bit_width: int | None,
        audit_last_sequence: int | None,
        audit_duplicates: int,
        audit_suspected_gaps: int,
        audit_backwards: int,
        audit_indeterminates: int,
        audit_missing_total: int,
    ) -> str:
        """Insert an imported session state in one atomic transaction.

        All state (offset, tail, frame total, last fragment, original
        response, audit progress) lands as a single row, so an import is
        either fully applied or not applied at all. Returns one of:

        * ``"imported"``  — the row was inserted;
        * ``"session_exists"`` — a session with this id already exists, the
          target state is left untouched (no overwrite);
        * ``"protocol_mismatch"`` — the exact protocol version is not
          registered with the given definition digest, nothing was written;
        * ``"audit_mismatch"`` — the checkpoint carries sequence-audit
          progress that the target database's exact protocol cannot support
          (no valid unsigned sequence field, or an effective bit width
          different from the checkpoint's modulus), nothing was written.

        Every check — definition digest, the protocol's sequence field and
        effective bit width, and the absence of a same-id session — runs
        inside the same ``BEGIN IMMEDIATE`` write transaction as the INSERT.
        A concurrent protocol registration (or competing import on another
        process) is serialised by the write lock and cannot make the checks
        pass against one committed protocol version while another version
        lands in the row: once this transaction holds the lock, the protocol
        row it verified cannot change underneath it before the INSERT.
        """
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            prow = conn.execute(
                "SELECT definition, definition_sha256 FROM protocols "
                "WHERE protocol_id = ? AND version = ?",
                (protocol_id, version),
            ).fetchone()
            if prow is None or prow["definition_sha256"] != definition_sha:
                outcome = "protocol_mismatch"
            elif audit_enabled and not self._protocol_supports_audit(
                prow, audit_bit_width
            ):
                outcome = "audit_mismatch"
            elif conn.execute(
                "SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone() is not None:
                outcome = "session_exists"
            else:
                try:
                    conn.execute(
                        "INSERT INTO sessions "
                        "(session_id, protocol_id, version, received_offset, tail_b64, "
                        " frames_total, last_chunk_offset, last_chunk_sha256, last_response, "
                        " audit_enabled, audit_bit_width, audit_last_sequence, "
                        " audit_duplicates, audit_suspected_gaps, audit_backwards, "
                        " audit_indeterminates, audit_missing_total) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            session_id,
                            protocol_id,
                            version,
                            received_offset,
                            tail_b64,
                            frames_total,
                            last_chunk_offset,
                            last_chunk_sha,
                            last_response_json,
                            int(audit_enabled),
                            audit_bit_width,
                            _encode_wide(audit_last_sequence),
                            audit_duplicates,
                            audit_suspected_gaps,
                            audit_backwards,
                            audit_indeterminates,
                            _encode_wide(audit_missing_total),
                        ),
                    )
                except sqlite3.IntegrityError:
                    # Another process sharing this database file inserted the
                    # same session_id between the existence check and the
                    # INSERT; the transaction rolls back, nothing is written.
                    outcome = "session_exists"
                else:
                    outcome = "imported"
            if outcome == "imported":
                conn.execute("COMMIT")
            else:
                conn.execute("ROLLBACK")
        except BaseException:
            # Commit (or any statement) raised: roll the still-open write
            # transaction back so nothing is left half applied.
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        return outcome

    @staticmethod
    def _protocol_supports_audit(prow: sqlite3.Row, audit_bit_width: int | None) -> bool:
        """Whether the exact verified protocol row carries the checkpoint's modulus.

        The pinned protocol must declare an unsigned integer sequence field of
        at least MIN_BIT_WIDTH effective bits whose width equals the
        checkpoint's audit bit width. Parsed from the protocol row read inside
        the import write transaction, so a tampered checkpoint (e.g. an 8-bit
        field carried as 2 bits) can never enter the target database and later
        appends can never audit against the wrong modulus.
        """
        proto = Database.row_to_protocol(prow)
        target_width = sequence_bit_width(proto)
        return (
            target_width is not None
            and target_width >= MIN_BIT_WIDTH
            and target_width == audit_bit_width
        )

    def save_session_append(
        self,
        session_id: str,
        *,
        expected_received_offset: int,
        received_offset: int,
        tail_b64: str,
        frames_total: int,
        last_chunk_offset: int,
        last_chunk_sha: str,
        last_response_json: str,
        audit_last_sequence: int | None,
        audit_duplicates: int,
        audit_suspected_gaps: int,
        audit_backwards: int,
        audit_indeterminates: int,
        audit_missing_total: int,
    ) -> bool:
        """Durably commit one accepted append; returns True when it won.

        Offset, tail, frame count, last chunk, its response and the sequence
        audit state move together in a single statement, so they take effect
        as one state and a crash/restart never loses or duplicates work.

        The UPDATE doubles as a compare-and-swap: it only applies while the
        session's committed ``received_offset`` is still the one this append
        was computed from. ``received_offset`` grows strictly with every
        committed append (chunks are non-empty), so it acts as the state
        version. When several service instances share this database, the
        in-process session lock cannot serialise them; this guard can. It
        returns False when another writer committed first — the row is then
        left untouched and the caller re-reads the newest state to decide
        between replay and conflict.
        """
        with self.conn:
            cur = self.conn.execute(
                "UPDATE sessions SET "
                "received_offset = ?, tail_b64 = ?, frames_total = ?, "
                "last_chunk_offset = ?, last_chunk_sha256 = ?, last_response = ?, "
                "audit_last_sequence = ?, audit_duplicates = ?, "
                "audit_suspected_gaps = ?, audit_backwards = ?, "
                "audit_indeterminates = ?, audit_missing_total = ?, "
                "updated_at = datetime('now') "
                "WHERE session_id = ? AND received_offset = ?",
                (
                    received_offset,
                    tail_b64,
                    frames_total,
                    last_chunk_offset,
                    last_chunk_sha,
                    last_response_json,
                    _encode_wide(audit_last_sequence),
                    audit_duplicates,
                    audit_suspected_gaps,
                    audit_backwards,
                    audit_indeterminates,
                    _encode_wide(audit_missing_total),
                    session_id,
                    expected_received_offset,
                ),
            )
        return cur.rowcount == 1
