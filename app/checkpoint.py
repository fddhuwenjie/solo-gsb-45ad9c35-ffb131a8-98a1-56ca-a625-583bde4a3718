"""Session checkpoint validation for database-to-database migration.

A checkpoint captures one *committed* collection-session state so the session
can continue against a fresh SQLite file under its original ``session_id``:

* the exact protocol version plus its definition digest;
* received offset and the raw pending tail;
* the cumulative frame count;
* the most recent fragment (offset + SHA-256) and its original response, so
  an identical resend replays verbatim instead of double counting;
* the sequence-audit progress when the session was created with it enabled
  (arbitrary-precision values included).

Import is deliberately strict. The checkpoint envelope is checked for
internal self-consistency (tail vs. offset, the stored response vs. the
stored offsets/tail, audit block vs. its enabled flag); the route layer then
verifies the target database has the exact protocol version registered with
the very same definition digest. Anything else makes the whole import fail
without touching existing target state.
"""
from __future__ import annotations

import base64
import binascii
import re

from pydantic import ValidationError

from .errors import SessionCheckpointInvalidError
from .models import (
    CHECKPOINT_FORMAT_VERSION,
    SessionAppendResponse,
    SessionCheckpoint,
)

_SESSION_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def validate_checkpoint(raw: object) -> tuple[SessionCheckpoint, SessionAppendResponse | None]:
    """Validate a raw checkpoint payload into a self-consistent checkpoint.

    Returns the parsed :class:`SessionCheckpoint` together with the parsed
    last-append response (or None for a never-appended session). Raises
    :class:`SessionCheckpointInvalidError` (structured 422) for a malformed
    envelope, unsupported format version or any internal contradiction.
    """
    problems: list[str] = []

    if not isinstance(raw, dict):
        raise SessionCheckpointInvalidError(
            message="checkpoint body must be a JSON object",
            details={"problems": ["body must be a JSON object"]},
        )

    try:
        checkpoint = SessionCheckpoint.model_validate(raw)
    except ValidationError as exc:
        # Pydantic raises ValidationError; surface it through the same
        # structured envelope as every other request-validation failure.
        problems = _validation_problems(exc)
        raise SessionCheckpointInvalidError(
            message="malformed session checkpoint",
            details={"problems": problems},
        ) from exc

    if checkpoint.format_version != CHECKPOINT_FORMAT_VERSION:
        raise SessionCheckpointInvalidError(
            message=(
                f"unsupported checkpoint format_version "
                f"{checkpoint.format_version}; expected {CHECKPOINT_FORMAT_VERSION}"
            ),
            details={
                "problems": [
                    f"unsupported format_version {checkpoint.format_version}",
                ],
                "format_version": checkpoint.format_version,
                "supported_format_version": CHECKPOINT_FORMAT_VERSION,
            },
        )

    _check_cross_fields(checkpoint, problems)

    if problems:
        raise SessionCheckpointInvalidError(
            message="session checkpoint is internally inconsistent",
            details={"problems": problems},
        )
    return checkpoint, checkpoint.last_response


def _validation_problems(exc: Exception) -> list[str]:
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return [str(exc)]
    problems: list[str] = []
    for err in errors():
        loc = ".".join(str(x) for x in err.get("loc", ())) or "<body>"
        problems.append(f"{loc}: {err.get('msg', 'invalid value')}")
    return problems or [str(exc)]


def _check_cross_fields(cp: SessionCheckpoint, problems: list[str]) -> None:
    """Structural self-consistency checks that do not need a target database."""
    if not _SESSION_ID_PATTERN.match(cp.session_id):
        problems.append("session_id must be 32 lowercase hexadecimal characters")
    if not _SHA256_PATTERN.match(cp.definition_sha256):
        problems.append("definition_sha256 must be a 64-char lowercase hex sha256 digest")

    tail_len = _decode_tail(cp, problems)

    if tail_len is not None and tail_len > cp.received_offset:
        problems.append(
            f"pending tail ({tail_len} bytes) is longer than received_offset "
            f"({cp.received_offset})"
        )

    pristine = cp.received_offset == 0
    if pristine:
        # A session that never accepted an append must carry no committed
        # fragment/response and an empty tail.
        if tail_len not in (None, 0):
            problems.append("received_offset is 0 but tail_b64 is not empty")
        if cp.last_chunk_offset is not None:
            problems.append("received_offset is 0 but last_chunk_offset is set")
        if cp.last_chunk_sha256 is not None:
            problems.append("received_offset is 0 but last_chunk_sha256 is set")
        if cp.last_response is not None:
            problems.append("received_offset is 0 but last_response is set")
    else:
        if cp.last_chunk_offset is None:
            problems.append("received_offset > 0 requires last_chunk_offset")
        if not cp.last_chunk_sha256:
            problems.append("received_offset > 0 requires last_chunk_sha256")
        elif not _SHA256_PATTERN.match(cp.last_chunk_sha256):
            problems.append("last_chunk_sha256 must be a 64-char lowercase hex sha256 digest")
        if cp.last_response is None:
            problems.append("received_offset > 0 requires the original last_response")
        if cp.last_chunk_offset is not None and cp.last_chunk_offset >= cp.received_offset:
            problems.append("last_chunk_offset must precede received_offset")

    _check_audit(cp, problems)

    if cp.last_response is not None:
        _check_response(cp, problems)


def _decode_tail(cp: SessionCheckpoint, problems: list[str]) -> int | None:
    try:
        return len(base64.b64decode(cp.tail_b64, validate=True))
    except (binascii.Error, ValueError) as exc:
        problems.append(f"tail_b64 is not valid base64: {exc}")
        return None


def _check_audit(cp: SessionCheckpoint, problems: list[str]) -> None:
    if cp.audit_enabled:
        if cp.sequence_audit is None:
            problems.append("audit_enabled is true but sequence_audit block is missing")
            return
    elif cp.sequence_audit is not None:
        problems.append("audit_enabled is false but a sequence_audit block is present")


def _check_response(cp: SessionCheckpoint, problems: list[str]) -> None:
    """The stored append response must restate the checkpoint state.

    An identical resend of the last fragment returns this stored response, so
    it must agree with the durable state: session/protocol identity, the
    pre-append received offset, the new offset, the tail bytes, cumulative
    frame count and (when audited) the audit baseline and totals. Frame and
    discard intervals must also fit inside the accepted byte range.
    """
    resp = cp.last_response
    assert resp is not None  # caller guarantees

    if resp.session_id != cp.session_id:
        problems.append("last_response.session_id does not match the checkpoint")
    if resp.protocol_id != cp.protocol_id:
        problems.append("last_response.protocol_id does not match the checkpoint")
    if resp.version != cp.version:
        problems.append("last_response.version does not match the checkpoint")
    if resp.next_offset != cp.received_offset:
        problems.append(
            "last_response.next_offset does not equal the checkpoint received_offset"
        )
    if resp.frames_total != cp.frames_total:
        problems.append("last_response.frames_total does not match the checkpoint")
    if resp.tail.payload_b64 != cp.tail_b64:
        problems.append("last_response.tail.payload_b64 does not match the checkpoint tail")
    if resp.tail.end != cp.received_offset:
        problems.append("last_response.tail.end does not equal received_offset")
    if resp.tail.start > resp.tail.end:
        problems.append("last_response.tail.start is after tail.end")
    if resp.received_offset != cp.last_chunk_offset:
        problems.append(
            "last_response.received_offset does not equal last_chunk_offset"
        )
    if resp.replayed:
        problems.append("stored last_response must not be marked replayed")
    if resp.frame_count != len(resp.frames):
        problems.append("last_response.frame_count does not match its frames length")
    if resp.frames_total < len(resp.frames):
        problems.append("last_response.frames_total is smaller than its frames length")

    for frame in resp.frames:
        if not (0 <= frame.start < frame.end <= cp.received_offset):
            problems.append(
                f"frame interval [{frame.start}, {frame.end}) falls outside the "
                f"accepted range [0, {cp.received_offset})"
            )
            break

    audit = cp.sequence_audit
    if audit is None:
        if resp.sequence_audit is not None:
            problems.append(
                "last_response carries sequence_audit but the checkpoint audit is disabled"
            )
        return
    if resp.sequence_audit is None:
        problems.append("last_response is missing its sequence_audit block")
        return
    report = resp.sequence_audit
    if report.bit_width != audit.bit_width:
        problems.append("sequence_audit.bit_width disagrees with the stored response")
    if report.last_sequence != audit.last_sequence:
        problems.append("sequence_audit.last_sequence disagrees with the stored response")
    if report.duplicates != audit.duplicates:
        problems.append("sequence_audit.duplicates disagrees with the stored response")
    if report.suspected_gaps != audit.suspected_gaps:
        problems.append("sequence_audit.suspected_gaps disagrees with the stored response")
    if report.backwards != audit.backwards:
        problems.append("sequence_audit.backwards disagrees with the stored response")
    if report.indeterminates != audit.indeterminates:
        problems.append("sequence_audit.indeterminates disagrees with the stored response")
    if report.missing_total != audit.missing_total:
        problems.append("sequence_audit.missing_total disagrees with the stored response")
    for anomaly in report.anomalies:
        if not (0 <= anomaly.frame_start < anomaly.frame_end <= cp.received_offset):
            problems.append("a sequence anomaly interval falls outside the accepted range")
            break
