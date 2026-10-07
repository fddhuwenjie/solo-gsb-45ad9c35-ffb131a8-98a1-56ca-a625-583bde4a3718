"""Pydantic models: protocol declarations and decode requests/responses."""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .errors import ProtocolValidationError

NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")

# CRC-16 presets from the CRC catalogue. Each tuple is
# (poly, init, refin, refout, xorout, check) where check is crc(b"123456789").
CRC_PRESETS: dict[str, tuple[int, int, bool, bool, int, int]] = {
    "CRC-16/CCITT-FALSE": (0x1021, 0xFFFF, False, False, 0x0000, 0x29B1),
    "CRC-16/XMODEM": (0x1021, 0x0000, False, False, 0x0000, 0x31C3),
    "CRC-16/X25": (0x1021, 0xFFFF, True, True, 0xFFFF, 0x906E),
    "CRC-16/MODBUS": (0x8005, 0xFFFF, True, True, 0x0000, 0x4B37),
    "CRC-16/IBM-SDLC": (0x1021, 0xFFFF, True, True, 0xFFFF, 0x906E),
    "CRC-16/ARC": (0x8005, 0x0000, True, True, 0x0000, 0xBB3D),
    "CRC-16/USB": (0x8005, 0xFFFF, True, True, 0xFFFF, 0xB4C8),
    "CRC-16/DNP": (0x3D65, 0x0000, True, True, 0xFFFF, 0xEA82),
}


class Endian(str, Enum):
    little = "little"
    big = "big"


def _validate_name(value: str) -> str:
    if not NAME_PATTERN.match(value):
        raise ValueError("must consist of 1-64 chars: letters, digits, '_', '.', '-'")
    return value


class LengthFieldSpec(BaseModel):
    """Where the frame length lives and how to interpret it.

    The length value read from the stream is the *logical (unescaped) payload
    size* expressed as ``frame_logical_length = raw_value + adjustment``.
    """

    offset: int = Field(..., ge=0, description="Offset of the length field after the sync bytes")
    size: Literal[1, 2, 4] = Field(..., description="Width of the length field in bytes")
    endian: Endian | None = Field(
        None, description="Per-field endianness; defaults to the protocol endianness"
    )
    adjustment: int = Field(
        0,
        ge=-(1 << 31),
        le=(1 << 31),
        description="Added to the raw length value (use a negative value when the "
        "length field counts header/trailer bytes that are not part of the payload)",
    )


class EscapingSpec(BaseModel):
    """DLE-style byte stuffing applied *inside* the sync delimiters."""

    enabled: bool = False
    escape_byte: int | None = Field(None, ge=0, le=255)
    xor_mask: int = Field(
        0x20,
        ge=1,
        le=255,
        description="A byte following the escape byte is XORed with this mask before stuffing",
    )
    escapes_sync: bool = Field(
        True, description="If true, each sync byte may appear on the wire in escaped form"
    )
    escaped_bytes: list[Annotated[int, Field(ge=0, le=255)]] | None = Field(
        None,
        description="Extra bytes (besides sync bytes and the escape byte) that get stuffed",
    )

    @model_validator(mode="after")
    def _check_enabled(self) -> "EscapingSpec":
        if self.enabled and self.escape_byte is None:
            raise ValueError("escape_byte is required when escaping is enabled")
        return self


class CrcSpec(BaseModel):
    """CRC-16 covering the whole logical frame body (excluding sync and CRC itself)."""

    preset: str | None = Field(
        None, description="Named CRC-16 preset; fills the individual parameters when supplied"
    )
    poly: int | None = Field(None, ge=1, le=0xFFFF)
    init: int = 0xFFFF
    refin: bool = False
    refout: bool = False
    xorout: int = 0
    offset: int = Field(
        ...,
        ge=0,
        description="Offset of the 2-byte CRC after the sync bytes, in logical (unescaped) space",
    )
    endian: Endian | None = Field(None, description="Wire byte order of the CRC; protocol default if null")
    verify: bool = True

    @model_validator(mode="before")
    @classmethod
    def _apply_preset(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        preset = data.get("preset")
        if preset:
            if preset not in CRC_PRESETS:
                raise ValueError(f"unknown CRC preset '{preset}'")
            poly, init, refin, refout, xorout, _check = CRC_PRESETS[preset]
            data = dict(data)
            data.setdefault("poly", poly)
            data.setdefault("init", init)
            data.setdefault("refin", refin)
            data.setdefault("refout", refout)
            data.setdefault("xorout", xorout)
        return data

    @model_validator(mode="after")
    def _check(self) -> "CrcSpec":
        if self.poly is None:
            raise ValueError("poly or a known preset must be supplied")
        return self


class FieldSpec(BaseModel):
    """A scalar field inside the logical frame body.

    ``offset``/``size`` address logical bytes after the sync bytes.
    For signed types the wire value is interpreted as two's complement, then
    ``value = signed * scale / divisor``. Optional ``bit_offset``/``bit_width``
    extract a sub-field from within the addressed integer.
    """

    name: str
    type: Literal["u8", "u16", "u24", "u32", "u64", "s8", "s16", "s24", "s32", "s64"]
    offset: int = Field(..., ge=0)
    endian: Endian | None = None
    bit_offset: int | None = Field(None, ge=0)
    bit_width: int | None = Field(None, ge=1, le=64)
    scale: Decimal = Field(default=Decimal(1), description="Multiplier applied to the raw integer")
    divisor: Decimal = Field(default=Decimal(1))
    min: Decimal | None = None
    max: Decimal | None = None
    signed: bool = False
    description: str = ""

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return _validate_name(v)

    @field_validator("scale", "divisor", "min", "max", mode="before")
    @classmethod
    def _decimal(cls, v: object) -> object:
        return Decimal(v) if isinstance(v, str) else v

    @model_validator(mode="after")
    def _check_bits(self) -> "FieldSpec":
        if self.divisor == 0:
            raise ValueError("divisor must not be zero")
        if (self.bit_offset is None) != (self.bit_width is None):
            raise ValueError("bit_offset and bit_width must be supplied together")
        if self.bit_width is not None:
            if self.bit_offset + self.bit_width > self.size_bytes * 8:
                raise ValueError("bit window exceeds field size")
        if self.signed and self.bit_width is not None:
            raise ValueError("signed bit-fields are not supported")
        return self

    @property
    def size_bytes(self) -> int:
        return int(self.type[1:]) // 8


class ProtocolDefinition(BaseModel):
    protocol_id: str
    version: int = Field(..., ge=1)
    sync: Annotated[list[Annotated[int, Field(ge=0, le=255)]], Field(min_length=1, max_length=8)]
    endian: Endian = Endian.big
    length_field: LengthFieldSpec
    escaping: EscapingSpec = Field(default_factory=EscapingSpec)
    crc: CrcSpec
    fields_: list[FieldSpec] = Field(default_factory=list, alias="fields")
    sequence_field: str | None = Field(
        None, description="Name of the field used as the frame sequence number"
    )
    min_frame_length: int = Field(
        0, ge=0, le=65536, description="Minimum accepted logical frame length (0 = structural minimum)"
    )
    max_frame_length: int = Field(
        4096, ge=1, le=65536, description="Hard upper bound for the logical frame length"
    )
    description: str = ""

    model_config = {"populate_by_name": True}

    @field_validator("protocol_id")
    @classmethod
    def _pid(cls, v: str) -> str:
        return _validate_name(v)

    @model_validator(mode="after")
    def _validate(self) -> "ProtocolDefinition":
        errs: list[str] = []

        if self.min_frame_length > self.max_frame_length:
            errs.append("min_frame_length must not exceed max_frame_length")

        sync_bytes = set(self.sync)
        lf = self.length_field
        # Structural minimum: header up to the end of the length field plus 2 CRC bytes.
        structural_min = lf.offset + lf.size + 2
        if self.crc.offset + 2 > structural_min:
            structural_min = self.crc.offset + 2
        if structural_min > self.max_frame_length:
            errs.append("length field / CRC cannot fit inside max_frame_length")
        if self.min_frame_length < structural_min:
            object.__setattr__(self, "min_frame_length", structural_min)

        esc = self.escaping
        if esc.enabled and esc.escape_byte in sync_bytes:
            errs.append("escape_byte must differ from every sync byte")

        seen: set[str] = set()
        for f in self.fields_:
            if f.name in seen:
                errs.append(f"duplicate field name '{f.name}'")
            seen.add(f.name)
            if f.offset + f.size_bytes > self.max_frame_length:
                errs.append(f"field '{f.name}' extends past max_frame_length")

        if self.sequence_field is not None and self.sequence_field not in seen:
            errs.append(f"sequence_field '{self.sequence_field}' is not declared in fields")

        if errs:
            raise ProtocolValidationError(
                details=[{"code": "INVALID_PROTOCOL", "msg": e} for e in errs],
                message="; ".join(errs),
            )
        return self


class DecodeRequest(BaseModel):
    protocol_id: str
    version: int | None = Field(None, ge=1, description="Defaults to the latest registered version")
    payload_b64: str = Field(..., description="Base64-encoded raw byte stream, may start mid-frame")


class DecodedField(BaseModel):
    name: str
    offset: int
    size: int
    raw: int
    value: float | int
    signed: bool


class DecodedFrame(BaseModel):
    start: int
    end: int
    logical_length: int
    sequence: int | None
    fields: list[DecodedField]
    crc_ok: bool


class DiscardedInterval(BaseModel):
    start: int
    end: int
    reason: str
    failed_attempts: list[dict] = Field(default_factory=list)


class Tail(BaseModel):
    start: int
    end: int
    payload_b64: str


class DecodeResponse(BaseModel):
    protocol_id: str
    version: int
    input_digest: str
    frames: list[DecodedFrame]
    discarded: list[DiscardedInterval]
    tail: Tail
    frame_count: int
    consumed: int
    cached: bool = False


class EncodeRequest(BaseModel):
    protocol_id: str
    version: int | None = Field(None, ge=1, description="Defaults to the latest registered version")
    logical_length: int = Field(
        ..., ge=1, le=65536, description="Logical (unescaped) frame length; unwritten bits stay 0"
    )
    fields: dict[str, Decimal] = Field(
        default_factory=dict,
        description="Physical values per field name; inverted to raw integers via scale/divisor",
    )

    @field_validator("fields", mode="before")
    @classmethod
    def _coerce_decimals(cls, v: object) -> object:
        if isinstance(v, dict):
            def coerce(x: object) -> object:
                if isinstance(x, str):
                    try:
                        return Decimal(x)
                    except InvalidOperation as exc:
                        raise ValueError(f"'{x}' is not a valid decimal number") from exc
                return x
            return {k: coerce(x) for k, x in v.items()}
        return v


class EncodedField(BaseModel):
    name: str
    offset: int
    size: int
    value: str = Field(..., description="Exact physical value written (decimal string)")
    raw: int = Field(..., description="Signed raw integer (value * divisor / scale)")
    wire: int = Field(..., description="Unsigned integer placed on the wire (two's complement if signed)")
    bit_offset: int | None
    bit_width: int | None
    signed: bool


class EncodeResponse(BaseModel):
    protocol_id: str
    version: int
    wire_b64: str = Field(..., description="Sync + escaped logical body, ready to transmit")
    logical_b64: str = Field(..., description="Unescaped logical frame body (after sync bytes)")
    logical_length: int
    wire_length: int
    length_value: int = Field(..., description="Raw value written into the length field")
    crc: str = Field(..., description="CRC-16 actually written, uppercase hex")
    fields: list[EncodedField]


# ---------------------------------------------------------------------------
# Streaming collection sessions
# ---------------------------------------------------------------------------


class CreateSessionRequest(BaseModel):
    protocol_id: str
    version: int = Field(
        ..., ge=1, description="Exact registered protocol version pinned to this session"
    )
    sequence_audit: bool = Field(
        False,
        description="Enable sequence-number continuity auditing for this session; "
        "the pinned protocol must declare sequence_field naming an unsigned "
        "integer field with an effective bit width of at least 2",
    )


class SessionAppendRequest(BaseModel):
    session_id: str
    expected_offset: int = Field(
        ..., ge=0, description="Session byte position at which this chunk must start"
    )
    chunk_b64: str = Field(
        ..., min_length=1, description="Non-empty base64 fragment of the arriving raw stream"
    )


class SequenceAnomaly(BaseModel):
    type: Literal["duplicate", "suspected_gap", "backward", "indeterminate"] = Field(
        ..., description="How this frame's raw sequence compares to the baseline"
    )
    frame_start: int = Field(..., description="Session offset where the anomalous frame starts")
    frame_end: int = Field(..., description="Session offset where the anomalous frame ends (exclusive)")
    previous_sequence: int = Field(
        ..., description="Baseline raw sequence (the previous valid frame)"
    )
    sequence: int = Field(..., description="Raw sequence of this frame")
    missing: int | None = Field(
        None, description="Inferred missing frame count; only set for suspected_gap"
    )


class SequenceAuditState(BaseModel):
    bit_width: int = Field(
        ..., description="Effective bit width of the sequence field; comparison modulus is 2**bit_width"
    )
    last_sequence: int | None = Field(
        ..., description="Raw sequence of the most recent valid frame (the next comparison baseline)"
    )
    duplicates: int = Field(..., description="Cumulative anomalies: same sequence as the baseline")
    suspected_gaps: int = Field(
        ..., description="Cumulative anomalies: forward jump of 2..half-1 steps"
    )
    backwards: int = Field(
        ..., description="Cumulative anomalies: jump larger than half the modulus"
    )
    indeterminates: int = Field(
        ..., description="Cumulative anomalies: jump of exactly half the modulus"
    )
    missing_total: int = Field(
        ..., description="Cumulative missing frames inferred from suspected gaps"
    )


class SequenceAuditReport(SequenceAuditState):
    anomalies: list[SequenceAnomaly] = Field(
        default_factory=list,
        description="Anomalies confirmed by this append, in frame order",
    )


class SessionAppendResponse(BaseModel):
    session_id: str
    protocol_id: str
    version: int
    received_offset: int = Field(..., description="Session bytes accepted before this append")
    next_offset: int = Field(..., description="Expected offset of the following append")
    frames: list[DecodedFrame] = Field(
        default_factory=list, description="Only frames newly confirmed by this append"
    )
    discarded: list[DiscardedInterval] = Field(
        default_factory=list,
        description="Only byte intervals newly discarded by this append (session offsets)",
    )
    tail: Tail = Field(..., description="New pending tail after this append (session offsets)")
    frame_count: int = Field(..., description="Frames newly produced by this append")
    frames_total: int = Field(..., description="Frames confirmed over the whole session so far")
    replayed: bool = Field(
        False,
        description="True when the identical chunk at the identical offset is resent: "
        "the stored response is returned verbatim and no frames are produced again",
    )
    sequence_audit: SequenceAuditReport | None = Field(
        None,
        description="Sequence continuity audit for this append; null unless the "
        "session was created with sequence_audit enabled",
    )


class SessionProgressResponse(BaseModel):
    session_id: str
    protocol_id: str
    version: int
    received_offset: int = Field(..., description="Total raw bytes durably accepted so far")
    next_offset: int
    tail: Tail
    frames_total: int
    last_chunk_offset: int | None
    last_chunk_sha256: str | None
    created_at: str
    updated_at: str
    sequence_audit: SequenceAuditState | None = Field(
        None,
        description="Cumulative sequence audit state; null unless the session "
        "was created with sequence_audit enabled",
    )


# ---------------------------------------------------------------------------
# Session checkpoints: portable export/import when swapping SQLite files
# ---------------------------------------------------------------------------


CHECKPOINT_FORMAT_VERSION = 1


class CheckpointAuditState(BaseModel):
    """Sequence audit progress carried by a session checkpoint.

    ``last_sequence`` / ``missing_total`` are arbitrary-precision ints on
    purpose: they may exceed SQLite's signed 64-bit INTEGER range and must
    survive the export/import round trip digit for digit.
    """

    model_config = {"extra": "forbid"}

    bit_width: int = Field(..., ge=2, le=64)
    last_sequence: int | None
    duplicates: int = Field(..., ge=0)
    suspected_gaps: int = Field(..., ge=0)
    backwards: int = Field(..., ge=0)
    indeterminates: int = Field(..., ge=0)
    missing_total: int = Field(..., ge=0)


class SessionCheckpoint(BaseModel):
    """One committed session state, portable between SQLite databases.

    Every field comes from the same committed snapshot (one joined read), so
    import can reproduce the session exactly: protocol version plus its
    definition digest, received offset, raw pending tail, cumulative frame
    count, the most recent fragment digest and its original response, and the
    sequence-audit progress when enabled.
    """

    model_config = {"extra": "forbid"}

    format_version: int = Field(
        CHECKPOINT_FORMAT_VERSION,
        description="Checkpoint envelope format version; only exactly supported versions import",
    )
    exported_at: str = Field(..., description="UTC ISO-8601 timestamp of the export")
    session_id: str
    protocol_id: str
    version: int = Field(..., ge=1)
    definition_sha256: str
    received_offset: int = Field(..., ge=0)
    tail_b64: str
    frames_total: int = Field(..., ge=0)
    last_chunk_offset: int | None = Field(None, ge=0)
    last_chunk_sha256: str | None = None
    last_response: SessionAppendResponse | None = Field(
        None,
        description="Original response of the most recent committed append; "
        "its identical resend must replay this verbatim",
    )
    audit_enabled: bool
    sequence_audit: CheckpointAuditState | None = None
