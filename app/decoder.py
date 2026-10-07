"""Binary frame resynchronisation engine.

Scan strategy
-------------
Every occurrence of the protocol sync pattern in the *raw* buffer is a
candidate frame start. For each candidate we walk the raw stream, undo byte
stuffing on the fly, and parse the length field to determine how many raw
bytes the frame occupies. Candidates whose declared length is out of bounds,
whose frame is incomplete (buffer ends too early), whose escaping is
malformed or whose CRC fails are rejected.

The winning frame is the valid candidate with the smallest exclusive end
offset (earliest ending frame). Ties on end offset between distinct valid
candidates mean the stream is ambiguous and produce a structured 422.
Everything before the winner is reported as a discarded interval with the
individual failed checks attached. The scan then continues after the frame;
bytes that might still become a frame (no sync, or only incomplete
candidates) are kept as the incomplete tail.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from decimal import Decimal

from .crc import build_table, crc16
from .errors import AmbiguousFrameError, FieldOutOfBoundsError
from .models import CrcSpec, Endian, EscapingSpec, FieldSpec, LengthFieldSpec, ProtocolDefinition

TYPE_SIZES = {"u8": 1, "u16": 2, "u24": 3, "u32": 4, "u64": 8,
              "s8": 1, "s16": 2, "s24": 3, "s32": 4, "s64": 8}

# Candidate evaluation outcomes.
INCOMPLETE = "incomplete"
LENGTH_OUT_OF_BOUNDS = "length_out_of_bounds"
BAD_ESCAPE = "malformed_escape"
CRC_FAIL = "crc_failed"
BAD_FIELD = "field_out_of_bounds"

_table_cache: dict[tuple, list[int]] = {}


def _crc_table(crcspec: "CrcSpec") -> list[int]:
    key = (crcspec.poly, crcspec.refin)
    table = _table_cache.get(key)
    if table is None:
        table = build_table(crcspec.poly, crcspec.refin)
        _table_cache[key] = table
    return table


@dataclass
class Candidate:
    sync_start: int
    end: int | None = None            # exclusive raw end, None while incomplete
    logical: bytes = b""
    logical_length: int = 0
    error: str | None = None
    detail: dict = field(default_factory=dict)


def _read_int(buf: bytes, offset: int, size: int, endian: str) -> int:
    return int.from_bytes(buf[offset:offset + size], endian)


def _stuffed_set(sync: bytes, esc: EscapingSpec) -> set[int]:
    stuffed: set[int] = {esc.escape_byte}  # type: ignore[arg-type]
    if esc.escapes_sync:
        stuffed.update(sync)
    if esc.escaped_bytes:
        stuffed.update(esc.escaped_bytes)
    return stuffed


def _collect(
    raw: bytes,
    start: int,
    proto: ProtocolDefinition,
) -> Candidate:
    """Walk the raw stream from one sync occurrence and classify it."""
    cand = Candidate(sync_start=start)
    n = len(raw)
    sync = bytes(proto.sync)
    esc = proto.escaping
    logical = bytearray()

    p = start + len(sync)  # raw read cursor right after the sync pattern
    out = 0                 # number of logical bytes produced
    crc_table = _crc_table(proto.crc)

    def need_logical(target: int) -> bool:
        """Consume raw bytes (unstuffing) until >=target logical bytes exist."""
        nonlocal p, out
        stuffed = _stuffed_set(sync, esc) if esc.enabled else set()
        while out < target:
            if p >= n:
                return False
            b = raw[p]
            if esc.enabled and b == esc.escape_byte:
                if p + 1 >= n:
                    return False  # dangling escape at buffer edge
                nb = raw[p + 1]
                decoded = nb ^ esc.xor_mask
                if decoded not in stuffed:
                    cand.error = BAD_ESCAPE
                    cand.detail = {"raw_offset": p, "byte": nb}
                    return False
                logical.append(decoded)
                p += 2
            else:
                logical.append(b)
                p += 1
            out += 1
        return True

    lf: LengthFieldSpec = proto.length_field
    endian = (lf.endian or proto.endian).value

    # 1) Read the length field.
    len_end_logical = lf.offset + lf.size
    if not need_logical(len_end_logical):
        cand.error = cand.error or INCOMPLETE
        cand.detail.setdefault("need_logical", len_end_logical)
        return cand
    raw_len = _read_int(bytes(logical), lf.offset, lf.size, endian)
    frame_len = raw_len + lf.adjustment
    if frame_len < proto.min_frame_length or frame_len > proto.max_frame_length:
        cand.error = LENGTH_OUT_OF_BOUNDS
        cand.detail = {
            "raw_length": raw_len,
            "adjustment": lf.adjustment,
            "declared_length": frame_len,
            "min": proto.min_frame_length,
            "max": proto.max_frame_length,
        }
        return cand

    # 2) Consume the whole declared logical body.
    if not need_logical(frame_len):
        cand.error = cand.error or INCOMPLETE
        cand.detail = {"declared_length": frame_len}
        return cand

    logical_bytes = bytes(logical)

    # 3) CRC over logical bytes except the 2 CRC bytes.
    crcspec: CrcSpec = proto.crc
    crc_end = crcspec.offset + 2
    if crc_end > frame_len:
        cand.error = BAD_FIELD
        cand.detail = {"element": "crc", "offset": crcspec.offset, "frame_length": frame_len}
        return cand
    crc_endian = (crcspec.endian or proto.endian).value
    expected = _read_int(logical_bytes, crcspec.offset, 2, crc_endian)
    if crcspec.verify:
        covered = logical_bytes[:crcspec.offset] + logical_bytes[crc_end:]
        actual = crc16(
            covered,
            poly=crcspec.poly,
            init=crcspec.init,
            refin=crcspec.refin,
            refout=crcspec.refout,
            xorout=crcspec.xorout,
            table=crc_table,
        )
        if actual != expected:
            cand.error = CRC_FAIL
            cand.detail = {"expected": f"{expected:04X}", "actual": f"{actual:04X}"}
            return cand

    cand.end = p
    cand.logical = logical_bytes
    cand.logical_length = frame_len
    return cand


def _find_syncs(raw: bytes, sync: bytes) -> list[int]:
    if not sync:
        return []
    out: list[int] = []
    p = raw.find(sync)
    while p != -1:
        out.append(p)
        p = raw.find(sync, p + 1)
    return out


def _partial_sync_length(raw: bytes, sync: bytes) -> int:
    """Length k (1..len(sync)-1) when raw ends with the first k sync bytes."""
    for k in range(len(sync) - 1, 0, -1):
        if raw.endswith(sync[:k]):
            return k
    return 0


def _parse_field(f: FieldSpec, logical: bytes, frame_start: int, default_endian: Endian) -> dict:
    size = TYPE_SIZES[f.type]
    if f.offset + size > len(logical):
        raise FieldOutOfBoundsError(
            message=f"field '{f.name}' at logical offset {f.offset} exceeds frame length {len(logical)}",
            details={
                "field": f.name,
                "offset": f.offset,
                "size": size,
                "frame_start": frame_start,
                "logical_length": len(logical),
            },
        )
    endian = (f.endian or default_endian).value
    raw_value = _read_int(logical, f.offset, size, endian)
    is_signed = f.type.startswith("s") or f.signed
    value_int = raw_value
    if f.type.startswith("s"):
        sign_bit = 1 << (size * 8 - 1)
        value_int = raw_value - (1 << (size * 8)) if raw_value & sign_bit else raw_value

    if f.bit_width is not None:
        shifted = raw_value >> f.bit_offset
        mask = (1 << f.bit_width) - 1
        raw_value = shifted & mask
        value_int = raw_value

    numeric: Decimal = Decimal(value_int) * f.scale / f.divisor
    result_num: float | int
    if f.scale == 1 and f.divisor == 1:
        result_num = value_int
    else:
        result_num = float(numeric)

    if f.min is not None and numeric < f.min:
        raise FieldOutOfBoundsError(
            message=f"field '{f.name}' value {numeric} below min {f.min}",
            details={"field": f.name, "value": str(numeric), "min": str(f.min)},
        )
    if f.max is not None and numeric > f.max:
        raise FieldOutOfBoundsError(
            message=f"field '{f.name}' value {numeric} above max {f.max}",
            details={"field": f.name, "value": str(numeric), "max": str(f.max)},
        )

    return {
        "name": f.name,
        "offset": f.offset,
        "size": size,
        "raw": raw_value,
        "value": result_num,
        "signed": is_signed,
    }


def _build_frame(cand: Candidate, proto: ProtocolDefinition) -> dict:
    fields = [
        _parse_field(f, cand.logical, cand.sync_start, proto.endian)
        for f in proto.fields_
    ]
    seq: int | None = None
    if proto.sequence_field is not None:
        for f in fields:
            if f["name"] == proto.sequence_field:
                seq = int(f["raw"])
                break
    return {
        "start": cand.sync_start,
        "end": cand.end,
        "logical_length": cand.logical_length,
        "sequence": seq,
        "fields": fields,
        "crc_ok": True,
    }


def decode_stream(raw: bytes, proto: ProtocolDefinition) -> dict:
    """Decode a raw byte stream, resynchronising from any half-frame start.

    Returns a dict with frames / discarded / tail entries (raw offsets).
    Raises FieldOutOfBoundsError or AmbiguousFrameError as structured 422s.
    """
    sync = bytes(proto.sync)
    frames: list[dict] = []
    discarded: list[dict] = []
    cursor = 0
    n = len(raw)

    while True:
        region = raw[cursor:]
        positions = [cursor + rel for rel in _find_syncs(region, sync)]

        candidates: list[Candidate] = []
        for pos in positions:
            cand = _collect(raw, pos, proto)
            if cand.error == BAD_FIELD:
                # Field/CRC geometry violation on a complete frame is a hard error.
                frame = {
                    "start": pos,
                    "end": cand.end,
                    "logical_length": cand.logical_length,
                }
                raise FieldOutOfBoundsError(details={**cand.detail, "frame": frame})
            candidates.append(cand)

        complete = [c for c in candidates if c.end is not None]

        if complete:
            min_end = min(c.end for c in complete)
            winners = [c for c in complete if c.end == min_end]
            if len(winners) > 1:
                # Same earliest end reached from distinct sync occurrences:
                # the stream does not identify a unique frame.
                raise AmbiguousFrameError(
                    message=(
                        f"{len(winners)} valid frames end at offset {min_end}; "
                        "cannot disambiguate frame boundary"
                    ),
                    details={
                        "end": min_end,
                        "candidates": [
                            {"start": c.sync_start, "logical_length": c.logical_length}
                            for c in winners
                        ],
                    },
                )
            winner = winners[0]

            # Every earlier candidate was rejected; report the skipped span once.
            if winner.sync_start > cursor:
                failed = [
                    {
                        "start": c.sync_start,
                        "error": c.error,
                        "detail": c.detail,
                    }
                    for c in candidates
                    if c.sync_start < winner.sync_start and c.error not in (INCOMPLETE, None)
                ]
                discarded.append({
                    "start": cursor,
                    "end": winner.sync_start,
                    "reason": "resync_failed_checks" if failed else "noise",
                    "failed_attempts": failed,
                })

            frames.append(_build_frame(winner, proto))
            cursor = winner.end
            continue

        # No complete frame remains in the buffer.
        if positions:
            recoverable = [c for c in candidates if c.error in (INCOMPLETE, BAD_ESCAPE, None)]
            if recoverable:
                # Earliest candidate that may still complete once more bytes arrive.
                tail_start = min(c.sync_start for c in recoverable)
            else:
                # Every remaining sync starts a provably bad frame: nothing is
                # recoverable; retain at most a dangling sync prefix as tail.
                last_sync = positions[-1]
                partial = _partial_sync_length(raw[cursor:], sync)
                tail_start = max(last_sync + 1, n - partial)
            if tail_start > cursor:
                failed = [
                    {"start": c.sync_start, "error": c.error, "detail": c.detail}
                    for c in candidates
                    if c.sync_start < tail_start and c.error not in (INCOMPLETE, None)
                ]
                discarded.append({
                    "start": cursor,
                    "end": tail_start,
                    "reason": "resync_failed_checks" if failed else "noise",
                    "failed_attempts": failed,
                })
        else:
            partial = _partial_sync_length(raw[cursor:], sync)
            tail_start = n - partial
            if tail_start > cursor:
                discarded.append({
                    "start": cursor,
                    "end": tail_start,
                    "reason": "noise",
                    "failed_attempts": [],
                })
        tail_bytes = raw[tail_start:]
        tail = {
            "start": tail_start,
            "end": n,
            "payload_b64": base64.b64encode(tail_bytes).decode(),
        }
        return {
            "frames": frames,
            "discarded": discarded,
            "tail": tail,
            "consumed": tail_start,
        }
