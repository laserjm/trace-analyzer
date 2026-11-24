"""AUTOSAR/COVESA DLT file ingest (storage header + standard/extended header,
verbose arguments rendered as text, non-verbose payloads as hex)."""

from __future__ import annotations

import struct
from pathlib import Path

from ..store import Batch, Store

MSG_TYPES = {0: "log", 1: "app_trace", 2: "nw_trace", 3: "control"}


def _id(b: bytes) -> str:
    return b.rstrip(b"\x00").decode("ascii", errors="replace")


def render_verbose(payload: bytes, n_args: int, big: bool) -> str:
    e = ">" if big else "<"
    parts, i = [], 0
    for _ in range(n_args):
        if i + 4 > len(payload):
            break
        tinfo = struct.unpack(e + "I", payload[i:i + 4])[0]
        i += 4
        tyle = tinfo & 0x0F
        size = {1: 1, 2: 2, 3: 4, 4: 8, 5: 16}.get(tyle, 0)
        if tinfo & 0x800:  # VARI: skip name (and unit for numerics)
            if tinfo & 0x200 or tinfo & 0x400:
                nlen = struct.unpack(e + "H", payload[i:i + 2])[0]
                i += 2 + nlen
            else:
                nlen, ulen = struct.unpack(e + "HH", payload[i:i + 4])
                i += 4 + nlen + ulen
        if tinfo & 0x1000:  # FIXP: quantisation + offset - not rendered
            return " ".join(parts + ["<fixed-point arg>"])
        if tinfo & 0x200:  # string
            slen = struct.unpack(e + "H", payload[i:i + 2])[0]
            parts.append(payload[i + 2:i + 2 + slen].rstrip(b"\x00").decode("utf-8", errors="replace"))
            i += 2 + slen
        elif tinfo & 0x400:  # raw
            rlen = struct.unpack(e + "H", payload[i:i + 2])[0]
            parts.append(payload[i + 2:i + 2 + rlen].hex(" "))
            i += 2 + rlen
        elif tinfo & 0x10:  # bool
            parts.append(str(bool(payload[i])))
            i += size or 1
        elif tinfo & (0x20 | 0x40) and size:  # sint / uint
            parts.append(str(int.from_bytes(payload[i:i + size], "big" if big else "little",
                                            signed=bool(tinfo & 0x20))))
            i += size
        elif tinfo & 0x80 and size in (4, 8):  # float
            parts.append(f"{struct.unpack(e + ('f' if size == 4 else 'd'), payload[i:i + size])[0]:g}")
            i += size
        else:
            parts.append(f"<arg type {tinfo:#x}>")
            break
    return " ".join(parts)


def ingest_dlt(store: Store, path: Path, file_id: int) -> dict:
    batch = Batch(store, "dlt", ["file_id", "ts", "ecu", "apid", "ctid", "msg_type", "level", "text"])
    buf = path.read_bytes()
    i, bad = 0, 0
    while i + 20 <= len(buf):
        if buf[i:i + 4] != b"DLT\x01":
            nxt = buf.find(b"DLT\x01", i + 1)  # resync after corruption
            if nxt < 0:
                break
            bad += 1
            i = nxt
            continue
        sec, usec = struct.unpack("<Ii", buf[i + 4:i + 12])
        ecu = _id(buf[i + 12:i + 16])
        p = i + 16
        htyp, _cnt, length = struct.unpack(">BBH", buf[p:p + 4])
        end = p + length
        q = p + 4
        if htyp & 0x04:  # WEID
            ecu = _id(buf[q:q + 4]) or ecu
            q += 4
        if htyp & 0x08:  # WSID
            q += 4
        if htyp & 0x10:  # WTMS (ECU uptime, 0.1 ms) - not stored yet
            q += 4
        apid = ctid = ""
        mtype, level, verbose, n_args = "log", None, False, 0
        if htyp & 0x01:  # UEH: extended header
            msin, n_args = buf[q], buf[q + 1]
            apid, ctid = _id(buf[q + 2:q + 6]), _id(buf[q + 6:q + 10])
            verbose = bool(msin & 0x01)
            mstp = (msin >> 1) & 0x07
            mtype = MSG_TYPES.get(mstp, str(mstp))
            level = (msin >> 4) & 0x0F if mstp == 0 else None
            q += 10
        payload = buf[q:end]
        big = bool(htyp & 0x02)
        if verbose:
            text = render_verbose(payload, n_args, big)
        elif len(payload) >= 4:
            mid = struct.unpack(">I" if big else "<I", payload[:4])[0]
            text = f"[non-verbose id={mid}] {payload[4:68].hex(' ')}"
        else:
            text = payload.hex(" ")
        batch.add(file_id, sec + usec / 1e6, ecu, apid, ctid, mtype, level, text)
        i = end
    batch.flush()
    return {"n_records": batch.count, "ts_min": batch.ts_min if batch.count else None,
            "ts_max": batch.ts_max if batch.count else None,
            "note": f"resynchronised {bad} times after corrupt data" if bad else None,
            "counts": {"dlt": batch.count}}
