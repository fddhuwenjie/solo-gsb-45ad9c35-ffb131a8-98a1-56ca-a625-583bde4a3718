from app.crc import crc16
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


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_multi_frame_with_leading_half_frame_and_tail(client):
    register(client)

    f1 = build_logical(seq=1, addr=3, temp_s16=2345, status=0b1100_1111)
    f2 = build_logical(seq=2, addr=3, temp_s16=-150, status=0)
    stream = (
        b"\x12\x34"          # noise / half-frame garbage
        + SYNC + f1
        + b"\x99"            # noise between frames
        + SYNC + f2
        + SYNC + f1[:4]      # incomplete frame tail (sync + partial body)
    )
    r = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(stream)})
    assert r.status_code == 200, r.text
    data = r.json()

    assert data["frame_count"] == 2
    fr0, fr1 = data["frames"]
    # frame 1 starts right after the 2 noise bytes
    assert (fr0["start"], fr0["end"]) == (2, 2 + 2 + 9)
    assert fr0["sequence"] == 1
    assert fr0["logical_length"] == 9
    values = {f["name"]: f for f in fr0["fields"]}
    assert values["temp"]["value"] == 23.45
    assert values["temp"]["signed"] is True
    assert values["state"]["raw"] == 0b111
    assert values["alarm"]["raw"] == 1
    assert values["seq"]["value"] == 1

    assert fr1["sequence"] == 2
    assert values["temp"]["size"] == 2
    assert next(f for f in fr1["fields"] if f["name"] == "temp")["value"] == -1.5

    assert [
        {"start": d["start"], "end": d["end"], "reason": d["reason"]}
        for d in data["discarded"]
    ] == [
        {"start": 0, "end": 2, "reason": "noise"},
        {"start": 13, "end": 14, "reason": "noise"},
    ]
    tail = data["tail"]
    assert tail["start"] == 2 + 2 + 9 + 1 + 2 + 9
    assert tail["end"] == len(stream)
    assert data["consumed"] == tail["start"]


def test_resync_after_bad_crc_picks_earliest_valid(client):
    register(client)

    good = build_logical(5, 7, 100)
    # Bad frame: correct length but CRC corrupted.
    bad = bytearray(build_logical(9, 7, 100))
    bad[7] ^= 0xFF
    stream = b"\x00" + SYNC + bytes(bad) + b"\x33" + SYNC + good
    r = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(stream)})
    assert r.status_code == 200, r.text
    data = r.json()

    assert len(data["frames"]) == 1
    frame = data["frames"][0]
    assert frame["sequence"] == 5
    # The rejected region covers noise, bad sync frame and trailing noise.
    assert data["discarded"][0]["start"] == 0
    assert data["discarded"][0]["end"] == frame["start"]
    attempts = data["discarded"][0]["failed_attempts"]
    assert any(a["error"] == "crc_failed" for a in attempts)
    crc_fail = next(a for a in attempts if a["error"] == "crc_failed")
    assert set(crc_fail["detail"]) == {"expected", "actual"}


def test_length_out_of_bounds_resyncs(client):
    register(client)

    bad = bytearray(9)
    bad[4] = 200  # declared length exceeds max_frame_length=64
    bad[6:8] = crc_ccitt(bytes(bad[:6]) + bytes(bad[8:])).to_bytes(2, "big")
    good = build_logical(8, 1, 0)
    stream = SYNC + bytes(bad) + SYNC + good

    r = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(stream)})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["frames"][0]["sequence"] == 8
    assert data["discarded"][0]["failed_attempts"][0]["error"] == "length_out_of_bounds"
    detail = data["discarded"][0]["failed_attempts"][0]["detail"]
    assert detail["declared_length"] == 200
    assert detail["max"] == 64


def test_escaped_frame(client):
    proto = standard_protocol(
        escaping={
            "enabled": True,
            "escape_byte": 0x7D,
            "xor_mask": 0x20,
            "escapes_sync": True,
        }
    )
    r = client.post("/protocols", json=proto)
    assert r.status_code == 201, r.text

    logical = build_logical(3, 0xAA, 0x1234)
    # Force the address byte to a sync byte and a CRC byte to the escape byte
    # by searching over the temp value until it happens.
    target = None
    for t in range(-30000, 30000):
        cand = build_logical(3, 0xAA, t)
        if 0x7D in cand[6:8]:
            target = cand
            break
    assert target is not None
    wire = SYNC + stuff(target)

    r = client.post("/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(wire)})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["frame_count"] == 1
    frame = data["frames"][0]
    assert frame["end"] == len(wire)  # stuffed frame is longer than logical 9
    assert frame["logical_length"] == 9
    assert frame["sequence"] == 3
    fields = {f["name"]: f for f in frame["fields"]}
    assert fields["addr"]["raw"] == 0xAA
    # nothing left over
    assert data["tail"]["start"] == data["tail"]["end"] == len(wire)


def test_field_below_min_returns_structured_422(client):
    register(
        client,
        fields=[
            {"name": "seq", "type": "u8", "offset": 0},
            {"name": "addr", "type": "u8", "offset": 1},
            {"name": "temp", "type": "s16", "offset": 2, "scale": "0.01", "min": "-40", "max": "125"},
        ],
        sequence_field="seq",
    )
    frame = build_logical(1, 1, -5000)  # -50.0 < -40
    r = client.post(
        "/decode",
        json={"protocol_id": "sensor-line", "payload_b64": b64(SYNC + frame)},
    )
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "FIELD_OUT_OF_BOUNDS"
    assert err["details"]["field"] == "temp"


def test_caching_same_input_digest(client):
    register(client)
    stream = SYNC + build_logical(4, 2, 600)
    body = {"protocol_id": "sensor-line", "payload_b64": b64(stream)}

    r1 = client.post("/decode", json=body)
    r2 = client.post("/decode", json=body)
    assert r1.json()["cached"] is False
    assert r2.json()["cached"] is True
    assert r1.json()["input_digest"] == r2.json()["input_digest"]


def test_invalid_base64_and_missing_protocol(client):
    r = client.post(
        "/decode", json={"protocol_id": "nope", "payload_b64": "###not-base64###"}
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "INVALID_BASE64"

    r = client.post("/decode", json={"protocol_id": "nope", "payload_b64": "AA=="})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "PROTOCOL_NOT_FOUND"


def test_invalid_protocol_structured_422(client):
    # sequence_field references a missing field
    bad = standard_protocol(sequence_field="nope")
    r = client.post("/protocols", json=bad)
    assert r.status_code == 422
    err = r.json()["error"]
    details = err["error"]["details"] if "error" in err else err["details"]
    codes = [d.get("code") for d in details]
    assert codes == ["INVALID_PROTOCOL"]


def test_version_conflict_and_version_resolution(client):
    register(client)
    r = client.post("/protocols", json=standard_protocol(description="changed"))
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "PROTOCOL_VERSION_CONFLICT"

    register(client, version=2)
    r = client.get("/protocols/sensor-line")
    assert r.json()["version"] == 2
    r = client.get("/protocols/sensor-line?version=1")
    assert r.json()["version"] == 1


def test_ambiguous_frames_same_end_returns_422(client):
    # Two valid CRC frames end at the same raw offset from distinct sync
    # occurrences: start 1 length 12, and start 5 length 8.
    register(client)
    buf = bytes.fromhex("67aa55710aaa550c7845ca08aab4be")
    assert [i for i in range(len(buf)) if buf.startswith(SYNC, i)] == [1, 5]

    r = client.post(
        "/decode", json={"protocol_id": "sensor-line", "payload_b64": b64(buf)}
    )
    assert r.status_code == 422, r.text
    err = r.json()["error"]
    assert err["code"] == "AMBIGUOUS_FRAME"
    starts = sorted(c["start"] for c in err["details"]["candidates"])
    assert starts == [1, 5]
    assert err["details"]["end"] == 15


def test_preset_check_values():
    # CRC catalogue check values for b"123456789"
    assert crc16(b"123456789", **CCITT) == 0x29B1
    assert crc16(
        b"123456789", poly=0x8005, init=0xFFFF, refin=True, refout=True, xorout=0
    ) == 0x4B37
