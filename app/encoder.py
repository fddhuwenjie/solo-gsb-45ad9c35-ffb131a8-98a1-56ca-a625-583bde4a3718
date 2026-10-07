"""Frame encoder: assemble a transmittable binary frame from field values.

Encoding pipeline
-----------------
1. Start from a zero-filled logical body of the requested ``logical_length``
   (every bit not written by a field stays 0).
2. Write each requested field: the physical value is inverted to a raw
   integer with ``raw = value * divisor / scale`` computed in ``Decimal``;
   the result must be exactly integral and fit the field's bit width and
   ``min``/``max``. Bits are placed at the same physical positions the
   decoder reads them from (endianness-aware). Where two fields cover the
   same physical bit, identical values are accepted, differing values are a
   structured 422. Fields may not occupy the length-field or CRC positions.
3. Derive the length field (``raw = logical_length - adjustment``), compute
   the CRC over the logical body minus the CRC bytes, then apply DLE
   escaping and prepend the sync bytes to obtain the wire frame.
4. Read-back verification: the wire frame is fed through the existing
   decoder; any mismatch against the requested values rejects the encode.
"""
from __future__ import annotations

import base64
from decimal import Decimal, DivisionByZero, InvalidOperation

from .crc import crc16
from .decoder import TYPE_SIZES, _crc_table, _stuffed_set, decode_stream
from .errors import (
    DerivedPositionConflictError,
    EncodeError,
    EncodeVerificationError,
    FieldOutOfBoundsError,
    LengthNotEncodableError,
    OverlappingWriteConflictError,
    UnknownFieldError,
    ValueNotRepresentableError,
)
from .models import ProtocolDefinition


def _spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _field_bit_positions(f, default_endian) -> list[int]:
    """Physical bit index (byte*8+bit, LSB first) for each bit of the raw value.

    Bit ``k`` of the integer the decoder reads from the field's bytes maps to
    the same physical position the decoder would read it back from.
    """
    size = TYPE_SIZES[f.type]
    endian = (f.endian or default_endian).value
    positions = []
    for k in range(size * 8):
        byte = k // 8
        bit = k % 8
        wire_byte = byte if endian == "little" else size - 1 - byte
        positions.append((f.offset + wire_byte) * 8 + bit)
    return positions


def _write_field(buf: bytearray, written: dict[int, tuple[int, str]], f, raw_signed: int,
                 default_endian) -> dict:
    """Place one field's bits into the logical body, honouring overlap rules."""
    size = TYPE_SIZES[f.type]
    is_signed_type = f.type.startswith("s")

    if f.bit_width is not None:
        if raw_signed < 0 or raw_signed >= (1 << f.bit_width):
            raise FieldOutOfBoundsError(
                message=(
                    f"field '{f.name}' raw value {raw_signed} does not fit "
                    f"{f.bit_width}-bit window"
                ),
                details={
                    "field": f.name,
                    "raw": raw_signed,
                    "bit_width": f.bit_width,
                    "max_raw": (1 << f.bit_width) - 1,
                },
            )
        container = raw_signed << f.bit_offset
        # Only the bit window itself is written; neighbouring bits of the
        # container byte belong to other fields sharing the byte.
        bit_range = range(f.bit_offset, f.bit_offset + f.bit_width)
    elif is_signed_type:
        limit = 1 << (size * 8 - 1)
        if not -limit <= raw_signed < limit:
            raise FieldOutOfBoundsError(
                message=(
                    f"field '{f.name}' raw value {raw_signed} does not fit "
                    f"signed {size * 8}-bit integer"
                ),
                details={
                    "field": f.name,
                    "raw": raw_signed,
                    "min_raw": -limit,
                    "max_raw": limit - 1,
                },
            )
        container = raw_signed & ((1 << (size * 8)) - 1)  # two's complement
        bit_range = range(size * 8)
    else:
        if not 0 <= raw_signed < (1 << (size * 8)):
            raise FieldOutOfBoundsError(
                message=(
                    f"field '{f.name}' raw value {raw_signed} does not fit "
                    f"unsigned {size * 8}-bit integer"
                ),
                details={
                    "field": f.name,
                    "raw": raw_signed,
                    "min_raw": 0,
                    "max_raw": (1 << (size * 8)) - 1,
                },
            )
        container = raw_signed
        bit_range = range(size * 8)

    positions = _field_bit_positions(f, default_endian)
    for k in bit_range:
        bit = (container >> k) & 1
        pos = positions[k]
        byte_idx, bit_idx = divmod(pos, 8)
        prev = written.get(pos)
        if prev is not None and prev[0] != bit:
            raise OverlappingWriteConflictError(
                message=(
                    f"fields '{prev[1]}' and '{f.name}' write different values "
                    f"to logical byte {byte_idx} bit {bit_idx}"
                ),
                details={
                    "field": f.name,
                    "conflicts_with": prev[1],
                    "byte": byte_idx,
                    "bit": bit_idx,
                    "existing_value": prev[0],
                    "new_value": bit,
                },
            )
        written[pos] = (bit, f.name)
        if bit:
            buf[byte_idx] |= 1 << bit_idx
        else:
            buf[byte_idx] &= ~(1 << bit_idx)

    wire = container if f.bit_width is None else raw_signed
    return {
        "name": f.name,
        "offset": f.offset,
        "size": size,
        "value": str(Decimal(raw_signed) * f.scale / f.divisor),
        "raw": raw_signed,
        "wire": wire,
        "bit_offset": f.bit_offset,
        "bit_width": f.bit_width,
        "signed": is_signed_type or f.signed,
    }


def encode_frame(proto: ProtocolDefinition, logical_length: int, field_values: dict) -> dict:
    """Build the wire frame for ``proto`` from ``field_values``.

    ``field_values`` maps field names to physical values (``Decimal``-exact).
    Raises structured 422 errors on any inconsistency.
    """
    lf = proto.length_field
    crcspec = proto.crc

    # --- geometry -----------------------------------------------------------
    if logical_length < proto.min_frame_length or logical_length > proto.max_frame_length:
        raise EncodeError(
            message=(
                f"logical_length {logical_length} outside allowed range "
                f"[{proto.min_frame_length}, {proto.max_frame_length}]"
            ),
            details={
                "logical_length": logical_length,
                "min": proto.min_frame_length,
                "max": proto.max_frame_length,
            },
        )
    len_span = (lf.offset, lf.offset + lf.size)
    crc_span = (crcspec.offset, crcspec.offset + 2)
    if _spans_overlap(*len_span, *crc_span):
        raise EncodeError(
            message="length field and CRC positions overlap; frame is not encodable",
            details={
                "length_field": {"offset": lf.offset, "size": lf.size},
                "crc": {"offset": crcspec.offset, "size": 2},
            },
        )
    if crc_span[1] > logical_length:
        raise EncodeError(
            message=(
                f"CRC at logical offset {crcspec.offset} does not fit inside "
                f"logical_length {logical_length}"
            ),
            details={"offset": crcspec.offset, "logical_length": logical_length},
        )

    # --- field values --------------------------------------------------------
    specs = {f.name: f for f in proto.fields_}
    unknown = sorted(name for name in field_values if name not in specs)
    if unknown:
        raise UnknownFieldError(
            message=f"unknown field(s) for protocol '{proto.protocol_id}': {', '.join(unknown)}",
            details={"unknown_fields": unknown, "known_fields": sorted(specs)},
        )

    buf = bytearray(logical_length)  # unwritten bits stay 0
    written: dict[int, tuple[int, str]] = {}
    details: list[dict] = []

    # Every declared field must fit the frame: the read-back decoder raises a
    # hard 422 when a field extends past the frame, so reject such requests up
    # front with the same error.
    for f in proto.fields_:
        if f.offset + TYPE_SIZES[f.type] > logical_length:
            raise FieldOutOfBoundsError(
                message=(
                    f"declared field '{f.name}' at logical offset {f.offset} "
                    f"exceeds logical_length {logical_length}"
                ),
                details={
                    "field": f.name,
                    "offset": f.offset,
                    "size": TYPE_SIZES[f.type],
                    "logical_length": logical_length,
                },
            )

    for f in proto.fields_:
        if f.name not in field_values:
            continue
        value = field_values[f.name]

        if not value.is_finite():
            raise ValueNotRepresentableError(
                message=f"field '{f.name}' value must be finite, got {value}",
                details={"field": f.name, "value": str(value)},
            )
        if f.min is not None and value < f.min:
            raise FieldOutOfBoundsError(
                message=f"field '{f.name}' value {value} below min {f.min}",
                details={"field": f.name, "value": str(value), "min": str(f.min)},
            )
        if f.max is not None and value > f.max:
            raise FieldOutOfBoundsError(
                message=f"field '{f.name}' value {value} above max {f.max}",
                details={"field": f.name, "value": str(value), "max": str(f.max)},
            )

        span = (f.offset, f.offset + TYPE_SIZES[f.type])
        for derived, (d_start, d_end) in (("length_field", len_span), ("crc", crc_span)):
            if _spans_overlap(*span, d_start, d_end):
                raise DerivedPositionConflictError(
                    message=(
                        f"field '{f.name}' occupies bytes reserved for the "
                        f"{derived} (logical [{d_start}, {d_end}))"
                    ),
                    details={
                        "field": f.name,
                        "offset": f.offset,
                        "size": TYPE_SIZES[f.type],
                        "derived": derived,
                        "derived_offset": d_start,
                        "derived_size": d_end - d_start,
                    },
                )

        try:
            raw_dec = value * f.divisor / f.scale
        except (DivisionByZero, InvalidOperation) as exc:
            raise ValueNotRepresentableError(
                message=(
                    f"field '{f.name}' has zero scale; value cannot be "
                    "converted to a raw integer"
                ),
                details={"field": f.name, "value": str(value), "scale": str(f.scale)},
            ) from exc
        if raw_dec != raw_dec.to_integral_value():
            raise ValueNotRepresentableError(
                message=(
                    f"field '{f.name}' value {value} is not exactly representable "
                    f"with scale {f.scale} / divisor {f.divisor}"
                ),
                details={
                    "field": f.name,
                    "value": str(value),
                    "scale": str(f.scale),
                    "divisor": str(f.divisor),
                    "raw": str(raw_dec),
                },
            )
        details.append(_write_field(buf, written, f, int(raw_dec), proto.endian))

    # --- derived elements ------------------------------------------------------
    raw_length = logical_length - lf.adjustment
    if not 0 <= raw_length < (1 << (lf.size * 8)):
        raise LengthNotEncodableError(
            message=(
                f"logical_length {logical_length} with adjustment {lf.adjustment} "
                f"needs length value {raw_length}, which does not fit the "
                f"{lf.size}-byte length field"
            ),
            details={
                "logical_length": logical_length,
                "adjustment": lf.adjustment,
                "raw_length": raw_length,
                "size": lf.size,
            },
        )
    len_endian = (lf.endian or proto.endian).value
    buf[lf.offset:lf.offset + lf.size] = raw_length.to_bytes(lf.size, len_endian)

    crc_endian = (crcspec.endian or proto.endian).value
    covered = bytes(buf[:crcspec.offset]) + bytes(buf[crcspec.offset + 2:])
    crc_value = crc16(
        covered,
        poly=crcspec.poly,
        init=crcspec.init,
        refin=crcspec.refin,
        refout=crcspec.refout,
        xorout=crcspec.xorout,
        table=_crc_table(crcspec),
    )
    buf[crcspec.offset:crcspec.offset + 2] = crc_value.to_bytes(2, crc_endian)

    logical = bytes(buf)

    # --- escaping + sync -------------------------------------------------------
    esc = proto.escaping
    if esc.enabled:
        stuffed = _stuffed_set(bytes(proto.sync), esc)
        body = bytearray()
        for b in logical:
            if b in stuffed:
                body += bytes((esc.escape_byte, b ^ esc.xor_mask))
            else:
                body.append(b)
        wire = bytes(proto.sync) + bytes(body)
    else:
        wire = bytes(proto.sync) + logical

    # --- read-back verification through the existing decoder ------------------
    decoded = decode_stream(wire, proto)
    problems: list[dict] = []
    if len(decoded["frames"]) != 1:
        problems.append({"check": "frame_count", "expected": 1, "actual": len(decoded["frames"])})
    else:
        frame = decoded["frames"][0]
        if frame["logical_length"] != logical_length:
            problems.append({
                "check": "logical_length",
                "expected": logical_length,
                "actual": frame["logical_length"],
            })
        decoded_fields = {f["name"]: f for f in frame["fields"]}
        for name, requested in field_values.items():
            got = decoded_fields.get(name)
            if got is None:
                continue  # field no longer declared: cannot happen for a registered protocol
            spec = specs[name]
            size = TYPE_SIZES[spec.type]
            if spec.type.startswith("s") and spec.bit_width is None:
                sign_bit = 1 << (size * 8 - 1)
                raw_signed = got["raw"] - (1 << (size * 8)) if got["raw"] & sign_bit else got["raw"]
            else:
                raw_signed = got["raw"]
            decoded_value = Decimal(raw_signed) * spec.scale / spec.divisor
            if decoded_value != requested:
                problems.append({
                    "check": "field_value",
                    "field": name,
                    "expected": str(requested),
                    "actual": str(decoded_value),
                })
    if decoded["tail"]["end"] != decoded["tail"]["start"]:
        problems.append({"check": "tail", "expected": "empty", "actual": decoded["tail"]})
    if problems:
        raise EncodeVerificationError(
            message="encoded frame failed read-back verification through the decoder",
            details={"problems": problems},
        )

    return {
        "wire_b64": base64.b64encode(wire).decode(),
        "logical_b64": base64.b64encode(logical).decode(),
        "logical_length": logical_length,
        "wire_length": len(wire),
        "length_value": raw_length,
        "crc": f"{crc_value:04X}",
        "fields": details,
    }
