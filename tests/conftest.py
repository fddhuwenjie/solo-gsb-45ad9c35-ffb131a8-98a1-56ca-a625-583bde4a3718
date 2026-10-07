import base64

import pytest

from app.config import Settings
from app.crc import crc16
from app.main import create_app

CCITT = dict(poly=0x1021, init=0xFFFF, refin=False, refout=False, xorout=0x0000)


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture()
def client(db_path):
    from fastapi.testclient import TestClient

    app = create_app(Settings(db_path=db_path, max_decode_bytes=1 << 20))
    with TestClient(app) as c:
        yield c


def crc_ccitt(body_without_crc: bytes) -> int:
    return crc16(body_without_crc, **CCITT)


def standard_protocol(**overrides):
    proto = {
        "protocol_id": "sensor-line",
        "version": 1,
        "sync": [0xAA, 0x55],
        "endian": "big",
        "length_field": {"offset": 4, "size": 1, "adjustment": 0},
        "crc": {"preset": "CRC-16/CCITT-FALSE", "offset": 6},
        "fields": [
            {"name": "seq", "type": "u8", "offset": 0},
            {"name": "addr", "type": "u8", "offset": 1},
            {"name": "temp", "type": "s16", "offset": 2, "scale": "0.01"},
            {"name": "state", "type": "u8", "offset": 5, "bit_offset": 0, "bit_width": 3},
            {"name": "alarm", "type": "u8", "offset": 5, "bit_offset": 3, "bit_width": 1},
        ],
        "sequence_field": "seq",
        "max_frame_length": 64,
    }
    proto.update(overrides)
    return proto


def build_logical(seq, addr, temp_s16: int, status: int = 0) -> bytes:
    """Logical 9-byte frame body (sync excluded)."""
    body = bytearray(9)
    body[0] = seq & 0xFF
    body[1] = addr & 0xFF
    body[2:4] = (temp_s16 & 0xFFFF).to_bytes(2, "big")
    body[4] = 9
    body[5] = status
    crc = crc_ccitt(bytes(body[:6]) + bytes(body[8:]))
    body[6:8] = crc.to_bytes(2, "big")
    return bytes(body)


def stuff(raw: bytes, sync=b"\xaa\x55", escape_byte=0x7D, xor_mask=0x20) -> bytes:
    protected = {sync[0], sync[1], escape_byte}
    out = bytearray()
    for b in raw:
        if b in protected:
            out += bytes([escape_byte, b ^ xor_mask])
        else:
            out.append(b)
    return bytes(out)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()
