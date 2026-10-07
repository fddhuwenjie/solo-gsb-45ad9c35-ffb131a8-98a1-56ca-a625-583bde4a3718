from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from decimal import Decimal

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .audit import (
    BACKWARD,
    DUPLICATE,
    INDETERMINATE,
    MIN_BIT_WIDTH,
    SUSPECTED_GAP,
    audit_frames,
    sequence_bit_width,
)
from .checkpoint import validate_checkpoint
from .config import Settings, get_settings
from .db import Database
from .decoder import decode_stream
from .encoder import encode_frame
from .errors import (
    APIError,
    InvalidBase64Error,
    PayloadTooLargeError,
    ProtocolNotFoundError,
    ProtocolVersionConflictError,
    SequenceAuditUnsupportedError,
    SessionAppendConflictError,
    SessionCheckpointInvalidError,
    SessionImportConflictError,
    SessionNotFoundError,
)
from .models import (
    CHECKPOINT_FORMAT_VERSION,
    CreateSessionRequest,
    DecodeRequest,
    DecodeResponse,
    EncodeRequest,
    EncodeResponse,
    ProtocolDefinition,
    SessionAppendRequest,
    SessionAppendResponse,
    SessionCheckpoint,
    SessionProgressResponse,
)


def _error_body(code: str, message: str, details=None) -> dict:
    body = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return body


def _validation_errors(errors: list[dict]) -> dict:
    details = []
    for err in errors:
        detail = {
            "code": err.get("type", "validation_error"),
            "loc": [str(x) for x in err.get("loc", [])],
            "msg": err.get("msg", ""),
        }
        ctx = err.get("ctx")
        if isinstance(ctx, dict) and isinstance(ctx.get("error"), APIError):
            inner: APIError = ctx["error"]
            detail["code"] = inner.code
            detail["msg"] = inner.message
            if inner.details is not None:
                detail["details"] = inner.details
        details.append(detail)
    return _error_body("VALIDATION_ERROR", "request validation failed", details)


def _judge_append(row, expected_offset: int, chunk_sha: str) -> dict | None:
    """Judge one append against one committed session state.

    Returns the stored response (marked ``replayed``) for an idempotent
    resend of the most recent chunk, raises ``SessionAppendConflictError``
    for rewrites and out-of-order/gapped submissions, and returns None when
    the append may proceed against this state. Used both for the first
    check and, after a lost commit race, against the freshest state.
    """
    # Idempotent retry of the most recent append: identical offset and
    # identical content returns the stored response without producing
    # any frame again.
    if (
        expected_offset == row["last_chunk_offset"]
        and chunk_sha == row["last_chunk_sha256"]
        and row["last_response"]
    ):
        response = json.loads(row["last_response"])
        response["replayed"] = True
        return response

    # Same offset as the last committed chunk but different content is
    # an attempted rewrite: reject before any state change. This is
    # checked before the gap test because, after a successful append,
    # last_chunk_offset is always smaller than received_offset.
    if expected_offset == row["last_chunk_offset"]:
        raise SessionAppendConflictError(
            message=(
                "offset already committed but chunk content differs from the "
                "previously accepted fragment"
            ),
            details={
                "reason": "content_mismatch",
                "expected_offset": expected_offset,
                "received_offset": row["received_offset"],
                "committed_sha256": row["last_chunk_sha256"],
                "submitted_sha256": chunk_sha,
            },
        )

    # Any other mismatch is rejected and leaves the state untouched:
    # a gap caused by concurrent/out-of-order submission.
    if expected_offset != row["received_offset"]:
        raise SessionAppendConflictError(
            message=(
                f"expected_offset {expected_offset} does not match session "
                f"received_offset {row['received_offset']}"
            ),
            details={
                "reason": "offset_mismatch",
                "expected_offset": expected_offset,
                "received_offset": row["received_offset"],
                "next_offset": row["received_offset"],
                "chunk_sha256": chunk_sha,
            },
        )

    return None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="Industrial Sensor Binary Frame Re-sync API",
        version="1.0.0",
        description="Register binary frame protocols and decode/resynchronise "
        "base64 byte streams that may start in the middle of a frame.",
    )
    app.state.settings = settings
    app.state.db = Database(settings.db_path)
    # One lock per collection session: serialises concurrent / out-of-order
    # appends to the same session for the lifetime of this process.
    app.state.session_locks = {}
    app.state.session_locks_guard = threading.Lock()

    def _session_lock(session_id: str) -> threading.Lock:
        with app.state.session_locks_guard:
            lock = app.state.session_locks.get(session_id)
            if lock is None:
                lock = threading.Lock()
                app.state.session_locks[session_id] = lock
            return lock

    # ---- structured error handlers ----------------------------------------

    @app.exception_handler(APIError)
    async def _api_error(_: Request, exc: APIError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def _request_validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content=_validation_errors(exc.errors()))

    @app.exception_handler(ValidationError)
    async def _pydantic_validation(_: Request, exc: ValidationError) -> JSONResponse:
        # Models validated explicitly inside a route (e.g. /encode parses JSON
        # with parse_float=Decimal) still report through the structured 422.
        return JSONResponse(status_code=422, content=_validation_errors(exc.errors()))

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
        return JSONResponse(
            status_code=500,
            content=_error_body("INTERNAL_ERROR", str(exc)),
        )

    # ---- routes ------------------------------------------------------------

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.post("/protocols", status_code=201)
    async def register_protocol(request: Request) -> dict:
        try:
            raw_body = await request.json()
        except Exception as exc:  # JSONDecodeError etc.
            raise InvalidBase64Error(
                code="INVALID_JSON", message=f"request body must be valid JSON: {exc}"
            ) from exc
        # Explicit validation so ProtocolValidationError (structured 422) propagates.
        proto = ProtocolDefinition.model_validate(raw_body)
        db: Database = app.state.db
        definition_sha = hashlib.sha256(
            proto.model_dump_json(by_alias=True).encode()
        ).hexdigest()

        existing = db.get_protocol_row(proto.protocol_id, proto.version)
        if existing is not None and existing["definition_sha256"] != definition_sha:
            raise ProtocolVersionConflictError(
                message=(
                    f"protocol '{proto.protocol_id}' version {proto.version} already exists "
                    "with a different definition"
                ),
                details={
                    "protocol_id": proto.protocol_id,
                    "version": proto.version,
                    "existing_sha256": existing["definition_sha256"],
                    "submitted_sha256": definition_sha,
                },
            )

        db.upsert_protocol(proto, definition_sha)
        return {
            "protocol_id": proto.protocol_id,
            "version": proto.version,
            "definition_sha256": definition_sha,
            "replaced": existing is not None,
        }

    @app.get("/protocols")
    async def list_protocols() -> dict:
        return {"protocols": app.state.db.list_protocols()}

    @app.get("/protocols/{protocol_id}")
    async def get_protocol(protocol_id: str, version: int | None = None) -> dict:
        found = app.state.db.find_protocol(protocol_id, version)
        if found is None:
            raise ProtocolNotFoundError(
                message=f"protocol '{protocol_id}'"
                + (f" version {version}" if version else "")
                + " not found"
            )
        proto, resolved_version = found
        return {
            "version": resolved_version,
            "definition": json.loads(proto.model_dump_json(by_alias=True)),
        }

    @app.post("/decode", response_model=DecodeResponse)
    async def decode(req: DecodeRequest) -> dict:
        db: Database = app.state.db

        try:
            raw = base64.b64decode(req.payload_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InvalidBase64Error(message=f"payload_b64 is not valid base64: {exc}") from exc

        if len(raw) > settings.max_decode_bytes:
            raise PayloadTooLargeError(
                message=(
                    f"decoded payload is {len(raw)} bytes; limit is {settings.max_decode_bytes} bytes"
                ),
                details={"size": len(raw), "limit": settings.max_decode_bytes},
            )

        found = db.find_protocol(req.protocol_id, req.version)
        if found is None:
            raise ProtocolNotFoundError(
                message=f"protocol '{req.protocol_id}'"
                + (f" version {req.version}" if req.version else "")
                + " not found"
            )
        proto, resolved_version = found

        input_digest = hashlib.sha256(raw).hexdigest()

        cached = db.get_cached(proto.protocol_id, resolved_version, input_digest)
        if cached is not None:
            cached["cached"] = True
            return cached

        result = decode_stream(raw, proto)
        response = {
            "protocol_id": proto.protocol_id,
            "version": resolved_version,
            "input_digest": input_digest,
            "frames": result["frames"],
            "discarded": result["discarded"],
            "tail": result["tail"],
            "frame_count": len(result["frames"]),
            "consumed": result["consumed"],
            "cached": False,
        }
        validated = DecodeResponse.model_validate(response)
        db.put_cached(proto.protocol_id, resolved_version, input_digest, validated)
        return response

    @app.post(
        "/encode",
        response_model=EncodeResponse,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        # Parsed manually (parse_float=Decimal); keep the docs schema explicit.
                        "schema": EncodeRequest.model_json_schema(ref_template="#/components/schemas/{model}"),
                    }
                },
            }
        },
    )
    async def encode(request: Request) -> dict:
        # Parse JSON with Decimal for all floating-point numbers so physical
        # values keep their exact decimal representation through the inversion.
        try:
            raw_body = json.loads(await request.body(), parse_float=Decimal)
        except Exception as exc:  # JSONDecodeError etc.
            raise InvalidBase64Error(
                code="INVALID_JSON", message=f"request body must be valid JSON: {exc}"
            ) from exc
        req = EncodeRequest.model_validate(raw_body)

        found = app.state.db.find_protocol(req.protocol_id, req.version)
        if found is None:
            raise ProtocolNotFoundError(
                message=f"protocol '{req.protocol_id}'"
                + (f" version {req.version}" if req.version else "")
                + " not found"
            )
        proto, resolved_version = found

        result = encode_frame(proto, req.logical_length, req.fields)
        response = {"protocol_id": proto.protocol_id, "version": resolved_version, **result}
        return EncodeResponse.model_validate(response).model_dump()

    # ---- streaming collection sessions ------------------------------------

    def _shift_to_session(result: dict, base: int) -> None:
        """Rebase every raw offset of one decode result onto session positions."""
        for frame in result["frames"]:
            frame["start"] += base
            frame["end"] += base
        for interval in result["discarded"]:
            interval["start"] += base
            interval["end"] += base
            for attempt in interval.get("failed_attempts", []):
                detail = attempt.get("detail")
                if isinstance(detail, dict) and "raw_offset" in detail:
                    detail["raw_offset"] += base
                attempt["start"] += base
        result["tail"]["start"] += base
        result["tail"]["end"] += base

    @app.post("/sessions", status_code=201)
    async def create_session(req: CreateSessionRequest) -> dict:
        db: Database = app.state.db
        found = db.find_protocol(req.protocol_id, req.version)
        if found is None:
            raise ProtocolNotFoundError(
                message=f"protocol '{req.protocol_id}' version {req.version} not found"
            )
        proto, resolved_version = found

        # Optional sequence continuity audit: the pinned protocol must declare
        # an unsigned integer sequence field of at least MIN_BIT_WIDTH
        # effective bits, otherwise the session is refused.
        audit_bit_width: int | None = None
        if req.sequence_audit:
            audit_bit_width = sequence_bit_width(proto)
            if audit_bit_width is None or audit_bit_width < MIN_BIT_WIDTH:
                raise SequenceAuditUnsupportedError(
                    message=(
                        "sequence audit requires the pinned protocol to declare "
                        "sequence_field naming an unsigned integer field with an "
                        f"effective bit width of at least {MIN_BIT_WIDTH}"
                    ),
                    details={
                        "protocol_id": proto.protocol_id,
                        "version": resolved_version,
                        "sequence_field": proto.sequence_field,
                        "bit_width": audit_bit_width,
                        "min_bit_width": MIN_BIT_WIDTH,
                    },
                )

        session_id = uuid.uuid4().hex
        db.create_session(
            session_id,
            req.protocol_id,
            resolved_version,
            audit_enabled=req.sequence_audit,
            audit_bit_width=audit_bit_width,
        )
        response = {
            "session_id": session_id,
            "protocol_id": req.protocol_id,
            "version": resolved_version,
            "received_offset": 0,
            "next_offset": 0,
            "tail": {"start": 0, "end": 0, "payload_b64": ""},
            "frames_total": 0,
        }
        if req.sequence_audit:
            response["sequence_audit"] = {
                "bit_width": audit_bit_width,
                "last_sequence": None,
                "duplicates": 0,
                "suspected_gaps": 0,
                "backwards": 0,
                "indeterminates": 0,
                "missing_total": 0,
            }
        return response

    @app.post("/sessions/append", response_model=SessionAppendResponse)
    async def session_append(req: SessionAppendRequest) -> dict:
        db: Database = app.state.db

        # Same-process appends to one session are serialised; cross-process
        # serialisation (several instances on one SQLite file) is enforced
        # by the compare-and-swap commit below.
        lock = _session_lock(req.session_id)
        with lock:
            row = db.get_session(req.session_id)
            if row is None:
                raise SessionNotFoundError(
                    message=f"session '{req.session_id}' not found"
                )

            protocol_id = row["protocol_id"]
            version = row["version"]
            received_offset = row["received_offset"]
            tail_b64 = row["tail_b64"]
            frames_total = row["frames_total"]

            try:
                chunk = base64.b64decode(req.chunk_b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise InvalidBase64Error(
                    message=f"chunk_b64 is not valid base64: {exc}"
                ) from exc

            chunk_sha = hashlib.sha256(chunk).hexdigest()

            replay = _judge_append(row, req.expected_offset, chunk_sha)
            if replay is not None:
                return replay

            pending_tail = base64.b64decode(tail_b64) if tail_b64 else b""
            combined = pending_tail + chunk
            if len(combined) > settings.max_decode_bytes:
                raise PayloadTooLargeError(
                    message=(
                        f"pending tail plus chunk is {len(combined)} bytes; limit is "
                        f"{settings.max_decode_bytes} bytes"
                    ),
                    details={"size": len(combined), "limit": settings.max_decode_bytes},
                )

            found = db.find_protocol(protocol_id, version)
            if found is None:  # pragma: no cover - session creation resolves it
                raise ProtocolNotFoundError(
                    message=f"protocol '{protocol_id}' version {version} not found"
                )
            proto, resolved_version = found

            # Reuse the existing resynchronisation decoder unchanged on
            # tail || chunk; only this append's new frames/discards come back.
            result = decode_stream(combined, proto)
            # Session position of local offset k inside (tail || chunk):
            # tail occupies [received-len(tail), received), chunk follows it,
            # so every local offset maps linearly with the tail-start base.
            base = received_offset - len(pending_tail)
            _shift_to_session(result, base)

            # Optional sequence continuity audit: only frames confirmed by
            # this append are judged, in order, against the persisted
            # baseline; every valid frame then becomes the next baseline.
            # Bad frames and the pending tail never reach this point.
            audit_enabled = bool(row["audit_enabled"])
            audit_last_sequence = row["audit_last_sequence"]
            audit_duplicates = row["audit_duplicates"]
            audit_suspected_gaps = row["audit_suspected_gaps"]
            audit_backwards = row["audit_backwards"]
            audit_indeterminates = row["audit_indeterminates"]
            audit_missing_total = row["audit_missing_total"]
            anomalies: list[dict] = []
            if audit_enabled:
                anomalies, audit_last_sequence, deltas = audit_frames(
                    result["frames"], audit_last_sequence, row["audit_bit_width"]
                )
                audit_duplicates += deltas[DUPLICATE]
                audit_suspected_gaps += deltas[SUSPECTED_GAP]
                audit_backwards += deltas[BACKWARD]
                audit_indeterminates += deltas[INDETERMINATE]
                audit_missing_total += deltas["missing"]

            new_tail_b64 = result["tail"]["payload_b64"]
            new_frames_total = frames_total + len(result["frames"])
            new_offset = received_offset + len(chunk)

            response = {
                "session_id": req.session_id,
                "protocol_id": protocol_id,
                "version": resolved_version,
                "received_offset": received_offset,
                "next_offset": new_offset,
                "frames": result["frames"],
                "discarded": result["discarded"],
                "tail": result["tail"],
                "frame_count": len(result["frames"]),
                "frames_total": new_frames_total,
                "replayed": False,
                "sequence_audit": (
                    {
                        "bit_width": row["audit_bit_width"],
                        "last_sequence": audit_last_sequence,
                        "anomalies": anomalies,
                        "duplicates": audit_duplicates,
                        "suspected_gaps": audit_suspected_gaps,
                        "backwards": audit_backwards,
                        "indeterminates": audit_indeterminates,
                        "missing_total": audit_missing_total,
                    }
                    if audit_enabled
                    else None
                ),
            }
            validated = SessionAppendResponse.model_validate(response)

            # Offset, tail, frame count, last chunk, this response and the
            # audit state commit as one state, guarded by the offset this
            # append was computed from. On error above (too large / decode
            # failure) nothing here runs, so neither the offset nor the audit
            # baseline advances; when the guard fails, another instance
            # committed first and nothing is written either.
            committed = db.save_session_append(
                req.session_id,
                expected_received_offset=received_offset,
                received_offset=new_offset,
                tail_b64=new_tail_b64,
                frames_total=new_frames_total,
                last_chunk_offset=received_offset,
                last_chunk_sha=chunk_sha,
                last_response_json=validated.model_dump_json(),
                audit_last_sequence=audit_last_sequence,
                audit_duplicates=audit_duplicates,
                audit_suspected_gaps=audit_suspected_gaps,
                audit_backwards=audit_backwards,
                audit_indeterminates=audit_indeterminates,
                audit_missing_total=audit_missing_total,
            )
            if not committed:
                # Lost the race against another instance sharing this
                # database: the state just read is stale. Judge this append
                # against the newest committed state instead — an identical
                # resend replays the stored response, anything else is a
                # conflict; either way the session state stays untouched.
                fresh = db.get_session(req.session_id)
                replay = _judge_append(fresh, req.expected_offset, chunk_sha)
                if replay is not None:
                    return replay
                # received_offset only moves forward, so a stale append can
                # never match the fresh offset: _judge_append always raised.
                raise SessionAppendConflictError(  # pragma: no cover
                    message="concurrent append committed first",
                    details={
                        "reason": "offset_mismatch",
                        "expected_offset": req.expected_offset,
                        "received_offset": fresh["received_offset"],
                        "next_offset": fresh["received_offset"],
                        "chunk_sha256": chunk_sha,
                    },
                )
            return response

    @app.get("/sessions/{session_id}", response_model=SessionProgressResponse)
    async def session_progress(session_id: str) -> dict:
        db: Database = app.state.db
        row = db.get_session(session_id)
        if row is None:
            raise SessionNotFoundError(message=f"session '{session_id}' not found")
        return _progress_from_row(row)

    # ---- session checkpoint export / import (SQLite migration) ------------

    @app.get(
        "/sessions/{session_id}/checkpoint",
        response_model=SessionCheckpoint,
    )
    async def export_session_checkpoint(session_id: str) -> dict:
        """Export one committed session state for replay on another database.

        The session row and its protocol definition digest are read in one
        joined statement — a single snapshot of one committed point — so the
        protocol version/digest, received offset, pending tail, cumulative
        frames, last fragment digest, original response and audit progress
        always describe the same committed state.
        """
        db: Database = app.state.db
        row = db.get_session_export(session_id)
        if row is None:
            raise SessionNotFoundError(message=f"session '{session_id}' not found")

        audit = None
        if row["audit_enabled"]:
            audit = {
                "bit_width": row["audit_bit_width"],
                "last_sequence": row["audit_last_sequence"],
                "duplicates": row["audit_duplicates"],
                "suspected_gaps": row["audit_suspected_gaps"],
                "backwards": row["audit_backwards"],
                "indeterminates": row["audit_indeterminates"],
                "missing_total": row["audit_missing_total"],
            }

        last_response = json.loads(row["last_response"]) if row["last_response"] else None
        return {
            "format_version": CHECKPOINT_FORMAT_VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "session_id": row["session_id"],
            "protocol_id": row["protocol_id"],
            "version": row["version"],
            "definition_sha256": row["protocol_definition_sha256"],
            "received_offset": row["received_offset"],
            "tail_b64": row["tail_b64"],
            "frames_total": row["frames_total"],
            "last_chunk_offset": row["last_chunk_offset"],
            "last_chunk_sha256": row["last_chunk_sha256"],
            "last_response": last_response,
            "audit_enabled": bool(row["audit_enabled"]),
            "sequence_audit": audit,
        }

    @app.post(
        "/sessions/import",
        response_model=SessionProgressResponse,
        status_code=201,
    )
    async def import_session_checkpoint(request: Request) -> dict:
        """Import a checkpointed session so it continues under its original id.

        Only accepted when the target database has the exact protocol version
        registered with an identical definition digest *and* a sequence field
        whose effective unsigned bit width matches the checkpoint's audit
        modulus, no session with the checkpoint id exists yet, and the
        checkpoint is internally consistent (tail start vs. received offset and
        decoded tail length, the stored original response self-consistent, and
        every carried raw sequence within the modulus range). Protocol
        verification and the session write run in one write transaction, so a
        concurrent registration cannot slip a different protocol in between.
        On success every state element lands in one row/transaction; on any
        failure the target database is left completely untouched.
        """
        try:
            raw = json.loads(await request.body())
        except Exception as exc:  # JSONDecodeError etc.
            raise InvalidBase64Error(
                code="INVALID_JSON", message=f"request body must be valid JSON: {exc}"
            ) from exc

        checkpoint, _ = validate_checkpoint(raw)

        db: Database = app.state.db
        # Serialise same-process imports of the same id against concurrent
        # appends/imports; cross-process safety is the atomic import txn.
        with _session_lock(checkpoint.session_id):
            audit = checkpoint.sequence_audit
            result = db.import_session_checkpoint(
                session_id=checkpoint.session_id,
                protocol_id=checkpoint.protocol_id,
                version=checkpoint.version,
                definition_sha=checkpoint.definition_sha256,
                received_offset=checkpoint.received_offset,
                tail_b64=checkpoint.tail_b64,
                frames_total=checkpoint.frames_total,
                last_chunk_offset=checkpoint.last_chunk_offset,
                last_chunk_sha=checkpoint.last_chunk_sha256,
                # Persist the exact validated response so an identical resend
                # of the last fragment replays it verbatim.
                last_response_json=(
                    checkpoint.last_response.model_dump_json()
                    if checkpoint.last_response is not None
                    else ""
                ),
                audit_enabled=checkpoint.audit_enabled,
                audit_bit_width=audit.bit_width if audit is not None else None,
                audit_last_sequence=audit.last_sequence if audit is not None else None,
                audit_duplicates=audit.duplicates if audit is not None else 0,
                audit_suspected_gaps=audit.suspected_gaps if audit is not None else 0,
                audit_backwards=audit.backwards if audit is not None else 0,
                audit_indeterminates=audit.indeterminates if audit is not None else 0,
                audit_missing_total=audit.missing_total if audit is not None else 0,
            )

            if result == "protocol_mismatch":
                raise SessionCheckpointInvalidError(
                    message=(
                        f"protocol '{checkpoint.protocol_id}' version "
                        f"{checkpoint.version} is not registered in the target "
                        "database with the checkpoint's exact definition digest"
                    ),
                    details={
                        "reason": "protocol_mismatch",
                        "protocol_id": checkpoint.protocol_id,
                        "version": checkpoint.version,
                        "definition_sha256": checkpoint.definition_sha256,
                    },
                )
            if result == "audit_mismatch":
                # The exact target protocol is registered, but it does not
                # carry the checkpoint's declared sequence modulus: either it
                # no longer declares a usable unsigned sequence field or its
                # effective bit width differs. Importing would resume the
                # audit against the wrong modulus, so the whole import fails.
                target = db.find_protocol(
                    checkpoint.protocol_id, checkpoint.version
                )
                target_width = (
                    sequence_bit_width(target[0]) if target is not None else None
                )
                raise SessionCheckpointInvalidError(
                    message=(
                        "the checkpoint's sequence_audit bit width does not "
                        "match the effective unsigned sequence-field bit width "
                        f"of protocol '{checkpoint.protocol_id}' version "
                        f"{checkpoint.version} registered in the target database"
                    ),
                    details={
                        "reason": "audit_mismatch",
                        "protocol_id": checkpoint.protocol_id,
                        "version": checkpoint.version,
                        "checkpoint_bit_width": (
                            checkpoint.sequence_audit.bit_width
                            if checkpoint.sequence_audit is not None
                            else None
                        ),
                        "target_bit_width": target_width,
                    },
                )
            if result == "session_exists":
                raise SessionImportConflictError(
                    message=(
                        f"session '{checkpoint.session_id}' already exists in the "
                        "target database; existing state is not overwritten"
                    ),
                    details={
                        "reason": "session_exists",
                        "session_id": checkpoint.session_id,
                    },
                )

            row = db.get_session(checkpoint.session_id)
            return _progress_from_row(row)

    return app


def _progress_from_row(row: dict) -> dict:
    """Build the session progress response body from one durable session row."""
    tail_bytes = base64.b64decode(row["tail_b64"]) if row["tail_b64"] else b""
    tail_start = row["received_offset"] - len(tail_bytes)
    audit = None
    if row["audit_enabled"]:
        audit = {
            "bit_width": row["audit_bit_width"],
            "last_sequence": row["audit_last_sequence"],
            "duplicates": row["audit_duplicates"],
            "suspected_gaps": row["audit_suspected_gaps"],
            "backwards": row["audit_backwards"],
            "indeterminates": row["audit_indeterminates"],
            "missing_total": row["audit_missing_total"],
        }
    return {
        "session_id": row["session_id"],
        "protocol_id": row["protocol_id"],
        "version": row["version"],
        "received_offset": row["received_offset"],
        "next_offset": row["received_offset"],
        "tail": {
            "start": tail_start,
            "end": row["received_offset"],
            "payload_b64": row["tail_b64"],
        },
        "frames_total": row["frames_total"],
        "last_chunk_offset": row["last_chunk_offset"],
        "last_chunk_sha256": row["last_chunk_sha256"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "sequence_audit": audit,
    }


app = create_app()
