from __future__ import annotations

from typing import Any


class APIError(Exception):
    """Base class for structured error responses."""

    status_code: int = 422
    code: str = "UNPROCESSABLE_ENTITY"

    def __init__(
        self,
        code: str | None = None,
        message: str = "",
        *,
        status_code: int | None = None,
        details: Any = None,
    ) -> None:
        self.code = code or self.code
        self.message = message or self.code.replace("_", " ").lower()
        if status_code is not None:
            self.status_code = status_code
        self.details = details
        super().__init__(self.message)


class ProtocolValidationError(APIError):
    status_code = 422
    code = "INVALID_PROTOCOL"


class PayloadTooLargeError(APIError):
    status_code = 413
    code = "PAYLOAD_TOO_LARGE"


class DecodeError(APIError):
    status_code = 422


class InvalidBase64Error(DecodeError):
    code = "INVALID_BASE64"


class ProtocolNotFoundError(APIError):
    status_code = 404
    code = "PROTOCOL_NOT_FOUND"


class ProtocolVersionConflictError(APIError):
    status_code = 409
    code = "PROTOCOL_VERSION_CONFLICT"


class SessionNotFoundError(APIError):
    status_code = 404
    code = "SESSION_NOT_FOUND"


class SessionAppendConflictError(APIError):
    status_code = 409
    code = "SESSION_APPEND_CONFLICT"


class SequenceAuditUnsupportedError(APIError):
    status_code = 422
    code = "SEQUENCE_AUDIT_UNSUPPORTED"


class SessionCheckpointInvalidError(APIError):
    status_code = 422
    code = "SESSION_IMPORT_INVALID"


class SessionImportConflictError(APIError):
    status_code = 409
    code = "SESSION_IMPORT_CONFLICT"


class FieldOutOfBoundsError(DecodeError):
    code = "FIELD_OUT_OF_BOUNDS"


class AmbiguousFrameError(DecodeError):
    code = "AMBIGUOUS_FRAME"


class EncodeError(APIError):
    status_code = 422
    code = "ENCODE_ERROR"


class UnknownFieldError(EncodeError):
    code = "UNKNOWN_FIELD"


class ValueNotRepresentableError(EncodeError):
    code = "VALUE_NOT_REPRESENTABLE"


class OverlappingWriteConflictError(EncodeError):
    code = "OVERLAPPING_WRITE_CONFLICT"


class DerivedPositionConflictError(EncodeError):
    code = "DERIVED_POSITION_CONFLICT"


class LengthNotEncodableError(EncodeError):
    code = "LENGTH_NOT_ENCODABLE"


class EncodeVerificationError(EncodeError):
    code = "ENCODE_VERIFICATION_FAILED"
