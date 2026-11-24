"""PCAP / PCAPNG ingest: Ethernet (VLAN, IPv4/IPv6, UDP/TCP), SOME/IP + SD, DoIP,
SoAd PDU-over-IP containers, and SocketCAN frames (linktype 227).

Own block reader instead of dpkt.pcapng.Reader, because automotive loggers write
multi-interface PCAPNG files (one interface per tap / bus) and dpkt only reads the
first interface. dpkt is used for the protocol layers.
"""

from __future__ import annotations

import socket
import struct
from collections import Counter
from pathlib import Path
from typing import Iterator

import dpkt

from ..store import Batch, Store

LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_SOCKETCAN, LINK_IPV4, LINK_IPV6, LINK_SLL2 = (
    1, 101, 113, 227, 228, 229, 276,
)

SOMEIP_MSG_TYPES = {0x00, 0x01, 0x02, 0x20, 0x21, 0x22, 0x23, 0x40, 0x41, 0x42,
                    0x80, 0x81, 0xA0, 0xA1, 0xC0, 0xC1}
SD_MESSAGE_ID = 0xFFFF8100
DOIP_PORT = 13400
SD_ENTRY_NAMES = {0x00: "FindService", 0x01: "OfferService", 0x06: "SubscribeEventgroup",
                  0x07: "SubscribeEventgroupAck"}


# --------------------------------------------------------------------------------------
# File readers
# --------------------------------------------------------------------------------------
def read_packets(path: Path) -> Iterator[tuple[float, str, int, bytes]]:
    """Yield (timestamp, interface_name, linktype, frame_bytes)."""
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(f)
        else:
            yield from _read_pcap(f)


def _read_pcap(f) -> Iterator[tuple[float, str, int, bytes]]:
    hdr = f.read(24)
    magic = hdr[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }
    if magic not in formats:
        raise ValueError("not a pcap/pcapng file")
    end, res = formats[magic]
    linktype = struct.unpack(end + "I", hdr[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(end + "IIII")
    while True:
        rh = f.read(16)
        if len(rh) < 16:
            return
        sec, frac, incl, _orig = rec.unpack(rh)
        yield sec + frac * res, "if0", linktype, f.read(incl)


def _read_pcapng(f) -> Iterator[tuple[float, str, int, bytes]]:
    end = "<"
    ifaces: list[tuple[str, int, float, float]] = []  # name, linktype, resolution, offset
    while True:
        head = f.read(8)
        if len(head) < 8:
            return
        btype = struct.unpack(end + "I", head[:4])[0]
        if btype == 0x0A0D0D0A:  # section header: (re)detect byte order
            bom = f.read(4)
            end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(end + "I", head[4:8])[0]
            f.read(blen - 12)
            ifaces = []
            continue
        blen = struct.unpack(end + "I", head[4:8])[0]
        body = f.read(blen - 8)[:-4]
        if btype == 0x00000001:  # interface description
            linktype = struct.unpack(end + "H", body[:2])[0]
            name, res, offset = f"if{len(ifaces)}", 1e-6, 0.0
            for code, val in _options(body[8:], end):
                if code == 2:
                    name = val.rstrip(b"\x00").decode(errors="replace")
                elif code == 9 and val:
                    b = val[0]
                    res = 2.0 ** -(b & 0x7F) if b & 0x80 else 10.0 ** -b
                elif code == 14 and len(val) == 8:
                    offset = float(struct.unpack(end + "q", val)[0])
            ifaces.append((name, linktype, res, offset))
        elif btype == 0x00000006:  # enhanced packet
            if_id, hi, lo, cap, _orig = struct.unpack(end + "IIIII", body[:20])
            name, linktype, res, offset = ifaces[if_id]
            yield offset + ((hi << 32) | lo) * res, name, linktype, body[20:20 + cap]
        elif btype == 0x00000003 and ifaces:  # simple packet (no timestamp)
            name, linktype, _, _ = ifaces[0]
            yield float("nan"), name, linktype, body[4:]


def _options(buf: bytes, end: str) -> Iterator[tuple[int, bytes]]:
    i = 0
    while i + 4 <= len(buf):
        code, length = struct.unpack(end + "HH", buf[i:i + 4])
        if code == 0:
            return
        yield code, buf[i + 4:i + 4 + length]
        i += 4 + ((length + 3) & ~3)


# --------------------------------------------------------------------------------------
# Protocol parsers (pure functions, unit-testable)
# --------------------------------------------------------------------------------------
def parse_someip(buf: bytes) -> list[tuple] | None:
    """Split a UDP payload / TCP segment into SOME/IP messages.
    Returns None unless the whole buffer tiles exactly into plausible messages."""
    out, i = [], 0
    while i < len(buf):
        if i + 16 > len(buf):
            return None
        msg_id, length, req_id, pver, iver, mtype, rc = struct.unpack(">IIIBBBB", buf[i:i + 16])
        if length < 8 or pver != 0x01 or mtype not in SOMEIP_MSG_TYPES or i + 8 + length > len(buf):
            return None
        out.append((msg_id >> 16, msg_id & 0xFFFF, req_id >> 16, req_id & 0xFFFF, iver, mtype, rc,
                    buf[i + 16:i + 8 + length]))
        i += 8 + length
    return out or None


def parse_sd(payload: bytes) -> list[tuple]:
    """SOME/IP-SD entries -> (entry_name, service, instance, major, ttl, eventgroup, endpoints)."""
    if len(payload) < 12:
        return []
    n_entries = struct.unpack(">I", payload[4:8])[0]
    entries = payload[8:8 + n_entries]
    opt_off = 8 + n_entries
    options: list[str] = []
    if opt_off + 4 <= len(payload):
        olen = struct.unpack(">I", payload[opt_off:opt_off + 4])[0]
        obuf = payload[opt_off + 4:opt_off + 4 + olen]
        j = 0
        while j + 3 <= len(obuf):
            length, otype = struct.unpack(">HB", obuf[j:j + 3])
            data = obuf[j + 4:j + 3 + length]
            if otype in (0x04, 0x14) and len(data) >= 8:  # IPv4 endpoint / multicast
                ip = socket.inet_ntoa(data[:4])
                proto = {0x06: "tcp", 0x11: "udp"}.get(data[5], hex(data[5]))
                options.append(f"{ip}:{struct.unpack('>H', data[6:8])[0]}/{proto}")
            elif otype in (0x06, 0x16) and len(data) >= 20:
                ip = socket.inet_ntop(socket.AF_INET6, data[:16])
                options.append(f"[{ip}]:{struct.unpack('>H', data[18:20])[0]}")
            else:
                options.append(f"opt{otype:#x}")
            j += 3 + length
    out = []
    for k in range(0, len(entries) - 15, 16):
        e = entries[k:k + 16]
        etype, i1, i2, nopt = e[0], e[1], e[2], e[3]
        service, instance = struct.unpack(">HH", e[4:8])
        major = e[8]
        ttl = int.from_bytes(e[9:12], "big")
        eventgroup = struct.unpack(">H", e[14:16])[0] if etype in (0x06, 0x07) else None
        name = SD_ENTRY_NAMES.get(etype, f"type{etype:#x}")
        if ttl == 0:
            name = {"OfferService": "StopOfferService", "SubscribeEventgroup": "StopSubscribeEventgroup",
                    "SubscribeEventgroupAck": "SubscribeEventgroupNack"}.get(name, name)
        idx = list(range(i1, i1 + (nopt >> 4))) + list(range(i2, i2 + (nopt & 0x0F)))
        eps = ",".join(options[x] for x in idx if x < len(options))
        out.append((name, service, instance, major, ttl, eventgroup, eps))
    return out


def parse_soad(buf: bytes, max_pdu: int = 65535) -> list[tuple[int, bytes]] | None:
    """AUTOSAR SoAd PDU header format: [header_id u32][length u32][data] repeated.
    Returns None unless the buffer tiles exactly."""
    out, i = [], 0
    while i < len(buf):
        if i + 8 > len(buf):
            return None
        hid, length = struct.unpack(">II", buf[i:i + 8])
        if length > max_pdu or i + 8 + length > len(buf):
            return None
        out.append((hid, buf[i + 8:i + 8 + length]))
        i += 8 + length
    return out or None


def parse_doip(buf: bytes) -> list[tuple[int, int | None, int | None, str]]:
    out, i = [], 0
    while i + 8 <= len(buf):
        ver, inv, ptype, length = struct.unpack(">BBHI", buf[i:i + 8])
        if ver ^ inv != 0xFF:
            break
        body = buf[i + 8:i + 8 + length]
        sa = ta = None
        uds = ""
        if ptype in (0x8001, 0x8002, 0x8003) and len(body) >= 4:
            sa, ta = struct.unpack(">HH", body[:4])
            uds = body[4:20].hex(" ")
        out.append((ptype, sa, ta, uds))
        i += 8 + length
    return out


# --------------------------------------------------------------------------------------
# Ingest
# --------------------------------------------------------------------------------------
def ingest_pcap(store: Store, path: Path, file_id: int) -> dict:
    eth = Batch(store, "eth_packets", ["file_id", "ts", "iface", "vlan", "src_ip", "dst_ip", "proto",
                                        "src_port", "dst_port", "length", "payload"])
    sip = Batch(store, "someip", ["file_id", "ts", "iface", "vlan", "src_ip", "dst_ip", "proto",
                                  "src_port", "dst_port", "service_id", "method_id", "client_id",
                                  "session_id", "iface_version", "msg_type", "return_code", "payload"])
    sd = Batch(store, "someip_sd", ["file_id", "ts", "src_ip", "dst_ip", "entry", "service_id",
                                    "instance_id", "major_version", "ttl", "eventgroup_id", "endpoints"])
    soad = Batch(store, "pdu_over_ip", ["file_id", "ts", "src_ip", "dst_ip", "proto", "src_port",
                                        "dst_port", "header_id", "length", "data"])
    doip = Batch(store, "doip", ["file_id", "ts", "src_ip", "dst_ip", "payload_type", "source_addr",
                                 "target_addr", "uds"])
    can = Batch(store, "can_frames", ["file_id", "ts", "channel", "can_id", "is_ext", "is_fd", "is_rx",
                                      "is_error", "dlc", "data"])
    skipped: Counter = Counter()

    for ts, iface, linktype, frame in read_packets(path):
        try:
            if linktype == LINK_SOCKETCAN:
                raw_id, length = struct.unpack(">IB", frame[:5])
                can.add(file_id, ts, iface, raw_id & 0x1FFFFFFF, bool(raw_id & 0x80000000),
                        len(frame) > 16, True, bool(raw_id & 0x20000000), length, bytes(frame[8:8 + length]))
                continue
            vlan, ip = None, None
            if linktype == LINK_ETHERNET:
                e = dpkt.ethernet.Ethernet(frame)
                if getattr(e, "vlan_tags", None):
                    vlan = e.vlan_tags[-1].id
                ip = e.data
            elif linktype in (LINK_RAW, LINK_IPV4, LINK_IPV6):
                ip = dpkt.ip.IP(frame) if frame[0] >> 4 == 4 else dpkt.ip6.IP6(frame)
            elif linktype == LINK_SLL:
                ip = dpkt.sll.SLL(frame).data
            elif linktype == LINK_SLL2:
                ip = dpkt.sll2.SLL2(frame).data
            else:
                skipped[f"linktype {linktype}"] += 1
                continue
            if isinstance(ip, dpkt.ip.IP):
                if ip.mf or ip.offset:
                    skipped["ip fragments (not reassembled)"] += 1
                    continue
                src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            elif isinstance(ip, dpkt.ip6.IP6):
                src, dst = socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)
            else:
                skipped[f"ethertype {getattr(e, 'type', 0):#06x}" if linktype == LINK_ETHERNET else "non-ip"] += 1
                continue
            l4 = ip.data
            if isinstance(l4, dpkt.udp.UDP):
                proto = "udp"
            elif isinstance(l4, dpkt.tcp.TCP):
                proto = "tcp"
            else:
                skipped["non udp/tcp ip"] += 1
                continue
            payload = bytes(l4.data)
            if proto == "tcp" and not payload:
                continue
            sp, dp = l4.sport, l4.dport
            eth.add(file_id, ts, iface, vlan, src, dst, proto, sp, dp, len(payload), payload)

            if DOIP_PORT in (sp, dp):
                for ptype, sa, ta, uds in parse_doip(payload):
                    doip.add(file_id, ts, src, dst, ptype, sa, ta, uds)
                continue
            msgs = parse_someip(payload)
            if msgs:
                for service, method, client, session, iver, mtype, rc, body in msgs:
                    if (service << 16 | method) == SD_MESSAGE_ID:
                        for entry in parse_sd(body):
                            sd.add(file_id, ts, src, dst, *entry)
                    else:
                        sip.add(file_id, ts, iface, vlan, src, dst, proto, sp, dp, service, method,
                                client, session, iver, mtype, rc, body)
                continue
            pdus = parse_soad(payload)
            if pdus:
                for hid, data in pdus:
                    soad.add(file_id, ts, src, dst, proto, sp, dp, hid, len(data), data)
        except (dpkt.UnpackError, struct.error, IndexError, ValueError):
            skipped["malformed"] += 1

    batches = (eth, sip, sd, soad, doip, can)
    for b in batches:
        b.flush()
    ts_min = min((b.ts_min for b in batches if b.count), default=None)
    ts_max = max((b.ts_max for b in batches if b.count), default=None)
    note = "; ".join(f"{k}: {v}" for k, v in skipped.most_common(8))
    return {"n_records": eth.count + can.count, "ts_min": ts_min, "ts_max": ts_max,
            "note": (f"skipped {note}" if note else None),
            "counts": {"eth_packets": eth.count, "someip": sip.count, "someip_sd": sd.count,
                       "pdu_over_ip": soad.count, "doip": doip.count, "can_frames": can.count}}
