"""Bit-level signal extraction and container-PDU unpacking."""

from __future__ import annotations

import struct


def extract(data: bytes, start: int, length: int, byte_order: str) -> int | None:
    """Raw unsigned value of a signal inside a PDU.

    AUTOSAR convention (ISignalToIPduMapping.startPosition, sawtooth bit numbering,
    bit 0 = LSB of byte 0):
      little endian (MOST-SIGNIFICANT-BYTE-LAST)  -> start is the signal's LSB
      big endian    (MOST-SIGNIFICANT-BYTE-FIRST) -> start is the signal's MSB
    Returns None if the signal does not fit into the data (short / truncated PDU).
    """
    if length <= 0:
        return None
    if byte_order == "little":
        if start + length > len(data) * 8:
            return None
        return (int.from_bytes(data, "little") >> start) & ((1 << length) - 1)
    value, pos = 0, start
    for _ in range(length):
        byte, bit = divmod(pos, 8)
        if byte >= len(data):
            return None
        value = (value << 1) | ((data[byte] >> bit) & 1)
        pos = (byte + 1) * 8 + 7 if bit == 0 else pos - 1
    return value


def bit_set(data: bytes, pos: int) -> bool | None:
    byte, bit = divmod(pos, 8)
    return None if byte >= len(data) else bool((data[byte] >> bit) & 1)


def unpack_container(data: bytes, header_type: str) -> list[tuple[int, bytes]]:
    """Split a container I-PDU into (contained_header_id, pdu_bytes).

    SHORT-HEADER: 24-bit id + 8-bit length; LONG-HEADER: 32-bit id + 32-bit length.
    Big-endian headers assumed (verify against your ComContainerHeaderByteOrder).
    A header id of 0 marks unused space and ends parsing.
    """
    out, i = [], 0
    long_hdr = header_type.upper().startswith("LONG")
    hsize = 8 if long_hdr else 4
    while i + hsize <= len(data):
        if long_hdr:
            hid, length = struct.unpack(">II", data[i:i + 8])
        else:
            hid, length = int.from_bytes(data[i:i + 3], "big"), data[i + 3]
        if hid == 0:
            break
        out.append((hid, data[i + hsize:i + hsize + length]))
        i += hsize + length
    return out
