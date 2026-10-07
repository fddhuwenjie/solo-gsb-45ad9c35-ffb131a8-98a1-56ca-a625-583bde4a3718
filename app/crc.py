"""Generic CRC-16 computation.

Parameters are the standard CRC catalogue tuple
(width=16, poly, init, refin, refout, xorout, check, residue).
"""
from __future__ import annotations


def _reflect(value: int, width: int) -> int:
    result = 0
    for i in range(width):
        if value & (1 << i):
            result |= 1 << (width - 1 - i)
    return result


def build_table(poly: int, refin: bool) -> list[int]:
    table: list[int] = []
    top_poly = _reflect(poly, 16) if refin else poly
    for byte in range(256):
        crc = byte if refin else byte << 8
        for _ in range(8):
            if refin:
                crc = (crc >> 1) ^ top_poly if crc & 1 else crc >> 1
            else:
                crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
        table.append(crc)
    return table


def crc16(
    data: bytes,
    *,
    poly: int,
    init: int,
    refin: bool,
    refout: bool,
    xorout: int,
    table: list[int] | None = None,
) -> int:
    table = table if table is not None else build_table(poly, refin)
    crc = init
    if refin:
        for byte in data:
            crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    else:
        for byte in data:
            crc = table[((crc >> 8) ^ byte) & 0xFF] ^ ((crc << 8) & 0xFFFF)
    if refout != refin:
        crc = _reflect(crc, 16)
    return crc ^ xorout
