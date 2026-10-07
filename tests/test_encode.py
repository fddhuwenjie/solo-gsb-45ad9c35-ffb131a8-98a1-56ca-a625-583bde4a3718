"""Tests for POST /encode: frame assembly, escaping, read-back verification."""
import base64
from decimal import Decimal

from app.crc import crc16
from app import encoder as encoder_mod
from app.decoder import decode_stream as real_decode_stream
from tests.conftest import (
    CCITT,
    b64,
    build_logical,
    crc_ccitt,
    standard_protocol,
    stuff,
)

SYNC = b"\xaa\x55"


def register(client, **overrides):
    r = client.post("/protocols", json=standard_protocol(**overrides))
    assert r.status_code == 201, r.text
    return r


def encode(client, body, **kw):
    return client.post("/encode", json=body, **kw)


# ---------------------------------------------------------------- round trip


def test_encode_basic_frame_roundtrip(client):
    register(client)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {
            "seq": 1,
            "addr": 3,
            "temp": "23.45",
            "state": 7,
            "alarm": 1,
        },
    })
    assert r.status_code == 200, r.text
    data = r.json()

    logical = base64.b64decode(data["logical_b64"])
    # state occupies bits 0..2 (0b111), alarm bit 3 -> status byte 0x0F;
    # unwritten bits 4..7 stay zero.
    assert logical == build_logical(1, 3, 2345, status=0x0F)

    wire = base64.b64decode(data["wire_b64"])
    assert wire == SYNC + logical
    assert data["wire_length"] == len(wire) == 11
    assert data["logical_length"] == 9
    assert data["length_value"] == 9
    assert data["crc"] == f"{crc_ccitt(bytes(logical[:6]) + bytes(logical[8:])):04X}"

    by_name = {f["name"]: f for f in data["fields"]}
    assert by_name["seq"]["raw"] == 1 and by_name["seq"]["wire"] == 1
    assert by_name["temp"]["raw"] == 2345 and by_name["temp"]["wire"] == 2345
    assert by_name["temp"]["value"] == "23.45"
    assert by_name["temp"]["signed"] is True
    assert by_name["state"]["bit_offset"] == 0 and by_name["state"]["bit_width"] == 3
    assert by_name["state"]["wire"] == 7

    # The produced frame must decode straight back with identical values.
    d = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(wire)})
    assert d.status_code == 200, d.text
    frame = d.json()["frames"][0]
    dec_fields = {f["name"]: f for f in frame["fields"]}
    assert dec_fields["temp"]["value"] == 23.45
    assert dec_fields["state"]["raw"] == 7
    assert dec_fields["alarm"]["raw"] == 1
    assert frame["logical_length"] == 9


def test_encode_json_float_is_exact_decimal(client):
    register(client)
    # A bare JSON number must be parsed exactly as Decimal, not a binary float.
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 2, "addr": 0, "temp": 23.45},
    })
    assert r.status_code == 200, r.text
    logical = base64.b64decode(r.json()["logical_b64"])
    assert logical == build_logical(2, 0, 2345)


def test_encode_signed_negative(client):
    register(client)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 2, "temp": "-1.5"},
    })
    assert r.status_code == 200, r.text
    logical = base64.b64decode(r.json()["logical_b64"])
    assert logical == build_logical(2, 0, -150)
    temp = next(f for f in r.json()["fields"] if f["name"] == "temp")
    assert temp["raw"] == -150
    assert temp["wire"] == (-150) & 0xFFFF  # two's complement on the wire
    assert temp["signed"] is True


def test_encode_unwritten_bits_are_zero(client):
    register(client)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 5},
    })
    assert r.status_code == 200, r.text
    logical = base64.b64decode(r.json()["logical_b64"])
    assert logical[0] == 5
    assert logical[1:6] == b"\x00\x00\x00\x09\x00"
    assert logical[8] == 0
    d = client.post("/decode", json={
        "protocol_id": "sensor-line", "payload_b64": b64(SYNC + logical),
    })
    fields = {f["name"]: f for f in d.json()["frames"][0]["fields"]}
    assert fields["addr"]["raw"] == 0
    assert fields["state"]["raw"] == 0
    assert fields["alarm"]["raw"] == 0


def test_encode_with_escaping(client):
    register(client, escaping={
        "enabled": True, "escape_byte": 0x7D, "xor_mask": 0x20, "escapes_sync": True,
    })
    # addr is a sync byte 0xAA; search a temp whose CRC bytes include 0x7D.
    target = None
    for t in range(-30000, 30000):
        cand = build_logical(3, 0xAA, t)
        if 0x7D in cand[6:8]:
            target = cand
            break
    assert target is not None
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 3, "addr": 0xAA, "temp": f"{t / 100:.2f}"},
    })
    assert r.status_code == 200, r.text
    data = r.json()
    wire = base64.b64decode(data["wire_b64"])
    assert base64.b64decode(data["logical_b64"]) == target
    assert wire == SYNC + stuff(target)
    assert data["wire_length"] > data["logical_length"]

    d = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(wire)})
    assert d.status_code == 200, d.text
    frame = d.json()["frames"][0]
    assert frame["end"] == len(wire)
    fields = {f["name"]: f for f in frame["fields"]}
    assert fields["addr"]["raw"] == 0xAA
    assert d.json()["tail"]["start"] == d.json()["tail"]["end"] == len(wire)


def test_encode_little_endian_modbus_with_adjustment(client):
    proto = {
        "protocol_id": "modbus-ish",
        "version": 1,
        "sync": [0x7E],
        "endian": "little",
        "length_field": {"offset": 0, "size": 2, "adjustment": -4},
        "crc": {"preset": "CRC-16/MODBUS", "offset": 6},
        "fields": [
            {"name": "seq", "type": "u8", "offset": 2},
            {"name": "pressure", "type": "u16", "offset": 3, "scale": "0.001"},
        ],
        "sequence_field": "seq",
        "max_frame_length": 64,
    }
    register(client, **proto)
    r = encode(client, {
        "protocol_id": "modbus-ish",
        "logical_length": 10,
        "fields": {"seq": 42, "pressure": "12.345"},
    })
    assert r.status_code == 200, r.text
    data = r.json()
    logical = base64.b64decode(data["logical_b64"])
    assert logical[0:2] == (10 + 4).to_bytes(2, "little")
    assert logical[2] == 42
    assert logical[3:5] == (12345).to_bytes(2, "little")
    expected_crc = crc16(bytes(logical[:6]) + bytes(logical[8:]),
                         poly=0x8005, init=0xFFFF, refin=True, refout=True, xorout=0)
    assert logical[6:8] == expected_crc.to_bytes(2, "little")
    assert data["length_value"] == 14

    wire = base64.b64decode(data["wire_b64"])
    d = client.post("/decode", json={"protocol_id": "modbus-ish", "payload_b64": b64(b"\xDE\xAD" + wire)})
    frame = d.json()["frames"][0]
    p = next(f for f in frame["fields"] if f["name"] == "pressure")
    assert abs(p["value"] - 12.345) < 1e-12


def test_encode_resolves_latest_version(client):
    register(client)
    register(client, version=2)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 1},
    })
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 2


# ------------------------------------------------------------- error replies


def test_encode_protocol_not_found(client):
    r = encode(client, {"protocol_id": "ghost", "logical_length": 9, "fields": {}})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "PROTOCOL_NOT_FOUND"


def test_encode_invalid_json_422(client):
    r = client.post("/encode", content=b"{not json", headers={"content-type": "application/json"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "INVALID_JSON"


def test_encode_inexact_scaled_value_422(client):
    register(client)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 1, "temp": "23.455"},  # 2345.5 / ... not integral
    })
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "VALUE_NOT_REPRESENTABLE"
    assert err["details"]["field"] == "temp"


def test_encode_bit_width_overflow_422(client):
    register(client)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 1, "temp": "400"},  # raw 40000 > s16 max 32767
    })
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "FIELD_OUT_OF_BOUNDS"

    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"state": 8},  # 4-bit window? 3-bit window; 8 overflows
    })
    assert r.status_code == 422
    assert r.json()["error"]["details"]["field"] == "state"


def test_encode_min_max_violation_422(client):
    register(client, fields=[
        {"name": "seq", "type": "u8", "offset": 0},
        {"name": "temp", "type": "s16", "offset": 2, "scale": "0.01", "min": "-40", "max": "125"},
    ], sequence_field="seq")
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"temp": "125.01"},
    })
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "FIELD_OUT_OF_BOUNDS"
    assert err["details"]["field"] == "temp"
    assert err["details"]["max"] == "125"


def test_encode_unknown_field_422(client):
    register(client)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"nope": 1},
    })
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "UNKNOWN_FIELD"
    assert err["details"]["unknown_fields"] == ["nope"]
    assert "seq" in err["details"]["known_fields"]


def test_encode_overlapping_bits_same_value_ok_conflict_422(client):
    register(client, sequence_field=None, fields=[
        {"name": "seq", "type": "u8", "offset": 0},
        {"name": "a", "type": "u8", "offset": 0},
        {"name": "b", "type": "u8", "offset": 0},
    ])
    body = {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 0x55, "a": 0x55, "b": 0x55},
    }
    r = encode(client, body)
    assert r.status_code == 200, r.text

    body["fields"]["b"] = 0x0F
    r = encode(client, body)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "OVERLAPPING_WRITE_CONFLICT"
    assert err["details"]["conflicts_with"] == "a"
    assert err["details"]["field"] == "b"
    assert err["details"]["byte"] == 0
    assert err["details"]["existing_value"] != err["details"]["new_value"]


def test_encode_field_may_not_occupy_length_or_crc_position(client):
    register(client, sequence_field=None, fields=[
        {"name": "seq", "type": "u8", "offset": 0},
        {"name": "lenbyte", "type": "u8", "offset": 4},
        {"name": "crcbyte", "type": "u8", "offset": 6},
    ])
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"lenbyte": 9},
    })
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "DERIVED_POSITION_CONFLICT"
    assert err["details"]["derived"] == "length_field"

    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"crcbyte": 0},
    })
    assert r.status_code == 422
    assert r.json()["error"]["details"]["derived"] == "crc"


def test_encode_logical_length_out_of_range_422(client):
    register(client)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 200,  # > max_frame_length 64
        "fields": {},
    })
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "ENCODE_ERROR"

    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 2,  # below structural minimum 8
        "fields": {},
    })
    assert r.status_code == 422


def test_encode_length_value_does_not_fit_field_422(client):
    register(client, max_frame_length=300)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 257,  # 1-byte length field cannot hold 257
        "fields": {},
    })
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "LENGTH_NOT_ENCODABLE"
    assert err["details"]["raw_length"] == 257


def test_encode_field_extends_past_frame_422(client):
    register(client, sequence_field=None, fields=[
        {"name": "seq", "type": "u8", "offset": 0},
        {"name": "big", "type": "u32", "offset": 8},  # 8+4 > 9, disjoint from CRC [6,8)
    ])
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"big": 0},
    })
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "FIELD_OUT_OF_BOUNDS"

    # Same rejection even when the overlong field is not among the values,
    # because the read-back decoder would reject the resulting frame.
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 1},
    })
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "FIELD_OUT_OF_BOUNDS"
    assert err["details"]["field"] == "big"


def test_encode_readback_mismatch_is_rejected(client, monkeypatch):
    register(client)

    def fake_decode_stream(wire, proto):
        result = real_decode_stream(wire, proto)
        # Corrupt the decoded temperature after the fact.
        for field in result["frames"][0]["fields"]:
            if field["name"] == "temp":
                field["raw"] = field["raw"] + 1
                field["value"] = 0
        return result

    monkeypatch.setattr(encoder_mod, "decode_stream", fake_decode_stream)
    r = encode(client, {
        "protocol_id": "sensor-line",
        "logical_length": 9,
        "fields": {"seq": 1, "temp": "23.45"},
    })
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "ENCODE_VERIFICATION_FAILED"
    problem = err["details"]["problems"][0]
    assert problem["check"] == "field_value"
    assert problem["field"] == "temp"
