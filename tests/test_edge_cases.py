"""Additional decoder edge cases."""
from tests.conftest import b64, build_logical, standard_protocol, stuff

SYNC = b"\xaa\x55"


def esc_protocol(**overrides):
    return standard_protocol(
        escaping={"enabled": True, "escape_byte": 0x7D, "xor_mask": 0x20, "escapes_sync": True},
        **overrides,
    )


def register(client, proto):
    r = client.post("/protocols", json=proto)
    assert r.status_code == 201, r.text


def test_dangling_escape_in_tail(client):
    register(client, esc_protocol())
    frame = SYNC + stuff(build_logical(2, 1, 100))
    stream = frame + SYNC + b"\x01\x02\x03\x7d"  # trailing dangling escape
    r = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(stream)})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["frame_count"] == 1
    # second sync with the partial body (incl. dangling escape) must stay in tail
    tail = data["tail"]
    assert tail["start"] == len(frame)
    assert tail["payload_b64"] == b64(SYNC + b"\x01\x02\x03\x7d")


def test_escaped_bad_crc_resyncs(client):
    register(client, esc_protocol())
    # good frame containing a stuffed sync byte in its address
    good = None
    for t in range(30000):
        cand = build_logical(7, 0xAA, t)
        if 0x55 in cand[6:8]:
            good = cand
            break
    assert good is not None
    good_wire = SYNC + stuff(good)

    bad_logical = bytearray(build_logical(99, 0, 0))
    bad_logical[5] ^= 0x0F  # corrupt payload but keep length
    bad_wire = SYNC + stuff(bytes(bad_logical))

    stream = bad_wire + good_wire
    r = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(stream)})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["frames"][0]["sequence"] == 7
    assert data["frames"][0]["start"] == len(bad_wire)
    reason = data["discarded"][0]
    assert reason["start"] == 0 and reason["end"] == len(bad_wire)
    assert any(a["error"] == "crc_failed" for a in reason["failed_attempts"])


def test_little_endian_modbus_with_adjustment(client):
    # Length field value includes sync(2) + length(2) overhead => adjustment = -4,
    # and the length field itself is 2 bytes little-endian. CRC-16/MODBUS LE.
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
    register(client, proto)

    from app.crc import crc16
    logical = bytearray(10)
    # logical view excludes the 1 sync byte: [lenLo,lenHi, seq, pLo,pHi, x, cLo,cHi, x,x]
    declared = 10 + 4  # frame length value counts sync + length bytes too
    logical[0:2] = declared.to_bytes(2, "little")
    logical[2] = 42
    pressure_raw = 12345
    logical[3:5] = pressure_raw.to_bytes(2, "little")
    crc = crc16(bytes(logical[:6]) + bytes(logical[8:]),
               poly=0x8005, init=0xFFFF, refin=True, refout=True, xorout=0)
    logical[6:8] = crc.to_bytes(2, "little")

    stream = b"\xDE\xAD" + b"\x7E" + bytes(logical)
    r = client.post("/decode", json={"protocol_id": "modbus-ish", "payload_b64": b64(stream)})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["frame_count"] == 1
    frame = data["frames"][0]
    assert frame["start"] == 2
    assert frame["end"] == 2 + 1 + 10
    assert frame["sequence"] == 42
    f = {x["name"]: x for x in frame["fields"]}
    assert abs(f["pressure"]["value"] - 12.345) < 1e-12
    assert data["discarded"][0]["start"] == 0 and data["discarded"][0]["end"] == 2


def test_sync_prefix_kept_as_tail(client):
    register(client, standard_protocol())
    # stream ends with the first byte of the sync pattern only
    stream = SYNC + build_logical(1, 1, 0) + b"\xff\xaa"
    r = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(stream)})
    data = r.json()
    assert data["tail"]["start"] == len(stream) - 1
    assert data["tail"]["payload_b64"] == b64(b"\xaa")


def test_field_extends_past_frame_is_422(client):
    register(client, standard_protocol(
        fields=[
            {"name": "seq", "type": "u8", "offset": 0},
            {"name": "big", "type": "u32", "offset": 7},  # frame logical len is 9 -> 7+4>9
        ],
        sequence_field="seq",
    ))
    r = client.post(
        "/decode",
        json={"protocol_id": "sensor-line", "payload_b64": b64(SYNC + build_logical(1, 1, 0))},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "FIELD_OUT_OF_BOUNDS"


def test_trailing_oversized_candidate_is_discarded_not_tail(client):
    register(client, standard_protocol())
    good = SYNC + build_logical(1, 1, 0)
    oversized = bytearray(9)
    oversized[4] = 200  # > max_frame_length
    stream = good + SYNC + bytes(oversized)

    r = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(stream)})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["frame_count"] == 1
    # tail is empty; the bad trailing frame was reported as a discarded interval
    assert data["tail"]["start"] == data["tail"]["end"] == len(stream)
    assert data["tail"]["payload_b64"] == ""
    last = data["discarded"][-1]
    assert last["start"] == len(good) and last["end"] == len(stream)
    assert last["failed_attempts"][0]["error"] == "length_out_of_bounds"
