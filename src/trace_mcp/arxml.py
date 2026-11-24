"""ARXML system description -> signal routes ("hops").

A hop is everything needed to find one occurrence of a signal on the wire:

    {"kind": "can", "can_id": 0x1A0, "is_ext": False, "cluster": "Body_CAN", "channel": "...",
     "pdu": "BCM_Status", "pdu_offset_bits": 0, "signal": "DoorLock", "start_bit": 8,
     "length": 4, "byte_order": "little", "update_bit": None,
     "container": None | {"header_type": "SHORT-HEADER", "contained_header_id": 0x12},
     "senders": [...], "receivers": [...]}

    {"kind": "pdu_over_ip", "header_id": 0x1001, "ports": [50001], ...same signal fields}

Routes are found by grouping all I-SIGNALs that share a SYSTEM-SIGNAL, plus explicit
gateway I-SIGNAL-MAPPINGs and I-PDU-MAPPINGs, then following each I-PDU to its carriers:
CAN frame triggerings, socket connections (PDU header id) and container I-PDUs.

Only the common AUTOSAR 4.x structures are covered. If your vendor tooling resolves
routes better, produce the same hop dicts and pass them to trace_signal as extra_hops,
or replace `SystemModel.routes()`.
"""

from __future__ import annotations

import re
from collections import defaultdict
from functools import cached_property
from pathlib import Path

from lxml import etree


def _ln(el) -> str:
    return etree.QName(el).localname


def _txt(el, tag: str) -> str | None:
    c = el.find(f"{{*}}{tag}")
    return c.text.strip() if c is not None and c.text else None


def _int(s: str | None) -> int | None:
    if s is None:
        return None
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _order(s: str | None) -> str:
    return "big" if s and "FIRST" in s.upper() else "little"


class SystemModel:
    def __init__(self, files: list[Path]):
        self.files = files
        self.by_path: dict[str, etree._Element] = {}
        self.path_of: dict[etree._Element, str] = {}
        self.roots = []
        for f in files:
            root = etree.parse(str(f), etree.XMLParser(huge_tree=True, remove_comments=True)).getroot()
            self.roots.append(root)
            self._index(root, "")
        self._build()

    # --- indexing ----------------------------------------------------------------
    def _index(self, el, prefix: str) -> None:
        for child in el:
            if not isinstance(child.tag, str):
                continue
            sn = child.find("{*}SHORT-NAME")
            if sn is not None and sn.text:
                p = f"{prefix}/{sn.text.strip()}"
                self.by_path[p] = child
                self.path_of[child] = p
                self._index(child, p)
            else:
                self._index(child, prefix)

    def _iter(self, tag: str):
        for p, el in self.by_path.items():
            if _ln(el) == tag:
                yield p, el

    def _iter_any(self, tag: str):
        """Also finds non-identifiable elements (no SHORT-NAME)."""
        for root in self.roots:
            yield from root.iter(f"{{*}}{tag}")

    def _ref(self, el, tag: str) -> str | None:
        return _txt(el, tag)

    def _refs(self, el, tag: str) -> list[str]:
        return [x.text.strip() for x in el.iter(f"{{*}}{tag}") if x.text]

    @staticmethod
    def _name(path: str | None) -> str:
        return path.rsplit("/", 1)[-1] if path else "?"

    @staticmethod
    def _parent(path: str) -> str:
        return path.rsplit("/", 1)[0]

    # --- model -------------------------------------------------------------------
    def _build(self) -> None:
        # ECU ports: port path -> (ecu, direction)
        self.port_info: dict[str, tuple[str, str]] = {}
        for tag in ("FRAME-PORT", "I-PDU-PORT", "I-SIGNAL-PORT"):
            for p, el in self._iter(tag):
                ecu = next((self._name(self.path_of[a]) for a in el.iterancestors()
                            if _ln(a) == "ECU-INSTANCE"), "?")
                self.port_info[p] = (ecu, (_txt(el, "COMMUNICATION-DIRECTION") or "?").upper())

        # I-SIGNALs
        self.signals: dict[str, dict] = {}
        for p, el in self._iter("I-SIGNAL"):
            self.signals[p] = {"name": self._name(p), "length": _int(_txt(el, "LENGTH")),
                               "system_signal": self._ref(el, "SYSTEM-SIGNAL-REF"),
                               "init_value": _txt(el, "VALUE")}

        # signal -> PDU mappings
        self.sig_in_pdu: dict[str, list[dict]] = defaultdict(list)
        self.pdu_len: dict[str, int | None] = {}
        self.contained_id: dict[str, tuple[int | None, int | None]] = {}
        for p, el in self._iter("I-SIGNAL-TO-I-PDU-MAPPING"):
            sig = self._ref(el, "I-SIGNAL-REF")
            if not sig:
                continue  # signal-group mapping: not supported yet
            pdu = self._parent(p)
            self.sig_in_pdu[sig].append({
                "pdu": pdu, "start_bit": _int(_txt(el, "START-POSITION")) or 0,
                "byte_order": _order(_txt(el, "PACKING-BYTE-ORDER")),
                "update_bit": _int(_txt(el, "UPDATE-INDICATION-BIT-POSITION")),
            })
        for p, el in self.by_path.items():
            if _ln(el).endswith("-PDU") or _ln(el) == "N-PDU":
                self.pdu_len[p] = _int(_txt(el, "LENGTH"))
                props = el.find("{*}CONTAINED-I-PDU-PROPS")
                if props is not None:
                    self.contained_id[p] = (_int(_txt(props, "HEADER-ID-SHORT-HEADER")),
                                            _int(_txt(props, "HEADER-ID-LONG-HEADER")))

        # PDU -> CAN frame
        self.pdu_in_frame: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for p, el in self._iter("PDU-TO-FRAME-MAPPING"):
            pdu = self._ref(el, "PDU-REF")
            if pdu:
                self.pdu_in_frame[pdu].append((self._parent(p), _int(_txt(el, "START-POSITION")) or 0))

        # CAN frame triggerings
        self.frame_trig: dict[str, list[dict]] = defaultdict(list)
        for p, el in self._iter("CAN-FRAME-TRIGGERING"):
            frame = self._ref(el, "FRAME-REF")
            if not frame:
                continue
            channel = self._parent(p)
            self.frame_trig[frame].append({
                "can_id": _int(_txt(el, "IDENTIFIER")),
                "is_ext": (_txt(el, "CAN-ADDRESSING-MODE") or "").upper() == "EXTENDED",
                "channel": self._name(channel), "cluster": self._name(self._parent(channel)),
                "ports": self._refs(el, "FRAME-PORT-REF"),
            })

        # PDU triggerings (any bus)
        self.pdu_trig: dict[str, dict] = {}
        for p, el in self._iter("PDU-TRIGGERING"):
            channel = self._parent(p)
            self.pdu_trig[p] = {"pdu": self._ref(el, "I-PDU-REF"), "channel": self._name(channel),
                                "cluster": self._name(self._parent(channel)),
                                "ports": self._refs(el, "I-PDU-PORT-REF")}

        # Socket connections: PDU header ids on Ethernet
        self.pdu_on_socket: dict[str, list[dict]] = defaultdict(list)
        for tag in ("SOCKET-CONNECTION-IPDU-IDENTIFIER", "SO-CON-I-PDU-IDENTIFIER"):
            for el in self._iter_any(tag):
                trig = self._ref(el, "PDU-TRIGGERING-REF")
                t = self.pdu_trig.get(trig or "")
                if not t or not t["pdu"]:
                    continue
                ports, ips = self._socket_endpoints(el)
                self.pdu_on_socket[t["pdu"]].append({
                    "header_id": _int(_txt(el, "HEADER-ID")), "ports": ports, "ips": ips,
                    "channel": t["channel"], "cluster": t["cluster"], "port_refs": t["ports"],
                })

        # Container I-PDUs
        self.pdu_in_container: dict[str, list[dict]] = defaultdict(list)
        for p, el in self._iter("CONTAINER-I-PDU"):
            htype = _txt(el, "HEADER-TYPE") or "SHORT-HEADER"
            for trig in self._refs(el, "CONTAINED-PDU-TRIGGERING-REF"):
                t = self.pdu_trig.get(trig)
                if t and t["pdu"]:
                    self.pdu_in_container[t["pdu"]].append({"container": p, "header_type": htype})

        # Gateway mappings
        sig_trig_to_sig = {p: self._ref(el, "I-SIGNAL-REF") for p, el in self._iter("I-SIGNAL-TRIGGERING")}
        self.gw_signal_edges: list[tuple[str, str, str]] = []
        self.gw_pdu_edges: list[tuple[str, str, str]] = []
        for p, gw in self._iter("GATEWAY"):
            ecu = self._name(self._ref(gw, "ECU-REF"))
            for m in gw.iter("{*}I-SIGNAL-MAPPING"):
                s = sig_trig_to_sig.get(self._ref(m, "SOURCE-SIGNAL-REF") or "")
                t = sig_trig_to_sig.get(self._ref(m, "TARGET-SIGNAL-REF") or "")
                if s and t:
                    self.gw_signal_edges.append((s, t, ecu))
            for m in gw.iter("{*}I-PDU-MAPPING"):
                s = self.pdu_trig.get(self._ref(m, "SOURCE-I-PDU-REF") or "", {}).get("pdu")
                tgt = m.find("{*}TARGET-I-PDU")
                t = self.pdu_trig.get(self._ref(tgt, "TARGET-I-PDU-REF") or "", {}).get("pdu") \
                    if tgt is not None else None
                if s and t:
                    self.gw_pdu_edges.append((s, t, ecu))

    def _socket_endpoints(self, el) -> tuple[list[int], list[str]]:
        ports, ips = set(), set()
        for anc in el.iterancestors():
            if _ln(anc) in ("SOCKET-CONNECTION", "SOCKET-CONNECTION-BUNDLE"):
                for ref in self._refs(anc, "CLIENT-PORT-REF") + self._refs(anc, "SERVER-PORT-REF"):
                    sa = self.by_path.get(ref)
                    if sa is None:
                        continue
                    for pn in sa.iter("{*}PORT-NUMBER"):
                        if pn.text and pn.text.strip().isdigit():
                            ports.add(int(pn.text))
                    ne_ref = next(sa.iter("{*}NETWORK-ENDPOINT-REF"), None)
                    ne = self.by_path.get(ne_ref.text.strip()) if ne_ref is not None and ne_ref.text else None
                    if ne is not None:
                        for ip in ne.iter("{*}IPV-4-ADDRESS"):
                            if ip.text:
                                ips.add(ip.text.strip())
            if _ln(anc) == "SOCKET-CONNECTION-BUNDLE":
                break
        return sorted(ports), sorted(ips)

    # --- queries -----------------------------------------------------------------
    @cached_property
    def by_system_signal(self) -> dict[str, list[str]]:
        d = defaultdict(list)
        for p, s in self.signals.items():
            if s["system_signal"]:
                d[s["system_signal"]].append(p)
        return d

    def find_signals(self, pattern: str, limit: int = 50) -> list[dict]:
        rx = re.compile(pattern, re.IGNORECASE)
        out = []
        for p, s in self.signals.items():
            if rx.search(s["name"]) or (s["system_signal"] and rx.search(self._name(s["system_signal"]))):
                out.append({"isignal": s["name"], "path": p,
                            "system_signal": self._name(s["system_signal"]),
                            "pdus": [self._name(m["pdu"]) for m in self.sig_in_pdu.get(p, [])]})
                if len(out) >= limit:
                    break
        return out

    def _signal_group(self, seeds: list[str]) -> tuple[set[str], list[str]]:
        group, notes, todo = set(), [], list(seeds)
        while todo:
            s = todo.pop()
            if s in group:
                continue
            group.add(s)
            sys_sig = self.signals.get(s, {}).get("system_signal")
            todo.extend(self.by_system_signal.get(sys_sig, []) if sys_sig else [])
            for a, b, ecu in self.gw_signal_edges:
                if a == s and b not in group:
                    notes.append(f"gateway {ecu}: signal {self._name(a)} -> {self._name(b)}")
                    todo.append(b)
                elif b == s and a not in group:
                    notes.append(f"gateway {ecu}: signal {self._name(a)} -> {self._name(b)}")
                    todo.append(a)
        return group, notes

    def _ecus(self, port_refs: list[str]) -> tuple[list[str], list[str]]:
        senders, receivers = set(), set()
        for r in port_refs:
            ecu, direction = self.port_info.get(r, ("?", "?"))
            (senders if direction == "OUT" else receivers).add(ecu)
        return sorted(senders), sorted(receivers)

    def _carriers(self, pdu: str, depth: int = 0) -> list[dict]:
        """Wire locations of a PDU: CAN frames, socket header ids, and (recursively) containers."""
        out = []
        for frame, pdu_start in self.pdu_in_frame.get(pdu, []):
            for t in self.frame_trig.get(frame, []):
                snd, rcv = self._ecus(t["ports"])
                out.append({"kind": "can", "can_id": t["can_id"], "is_ext": t["is_ext"],
                            "cluster": t["cluster"], "channel": t["channel"],
                            "frame": self._name(frame), "pdu_offset_bits": pdu_start,
                            "senders": snd, "receivers": rcv})
        for s in self.pdu_on_socket.get(pdu, []):
            snd, rcv = self._ecus(s["port_refs"])
            out.append({"kind": "pdu_over_ip", "header_id": s["header_id"], "ports": s["ports"],
                        "ips": s["ips"], "cluster": s["cluster"], "channel": s["channel"],
                        "pdu_offset_bits": 0, "senders": snd, "receivers": rcv})
        if depth < 3:
            for c in self.pdu_in_container.get(pdu, []):
                short_id, long_id = self.contained_id.get(pdu, (None, None))
                cid = long_id if c["header_type"].upper().startswith("LONG") else short_id
                for carrier in self._carriers(c["container"], depth + 1):
                    carrier = dict(carrier)
                    carrier["container"] = {"pdu": self._name(c["container"]),
                                            "header_type": c["header_type"], "contained_header_id": cid}
                    carrier["pdu_offset_bits"] = 0
                    out.append(carrier)
        return out

    def routes(self, signal: str) -> dict:
        """All hops of a signal. `signal` is an I-SIGNAL or SYSTEM-SIGNAL short name
        (case-insensitive exact match) or a full ARXML path."""
        seeds = [p for p, s in self.signals.items()
                 if p == signal or s["name"].lower() == signal.lower()
                 or self._name(s["system_signal"]).lower() == signal.lower()]
        if not seeds:
            return {"signal": signal, "hops": [], "notes": ["no I-SIGNAL or SYSTEM-SIGNAL with that name"]}
        group, notes = self._signal_group(seeds)
        hops, seen = [], set()
        for sig in sorted(group):
            for m in self.sig_in_pdu.get(sig, []):
                pdus = [m["pdu"]]
                for a, b, ecu in self.gw_pdu_edges:
                    if a == m["pdu"]:
                        pdus.append(b)
                        notes.append(f"gateway {ecu}: PDU {self._name(a)} -> {self._name(b)} "
                                     "(assumed same layout)")
                for pdu in pdus:
                    for c in self._carriers(pdu):
                        hop = {**c, "pdu": self._name(pdu), "pdu_length": self.pdu_len.get(pdu),
                               "signal": self.signals[sig]["name"], "start_bit": m["start_bit"],
                               "length": self.signals[sig]["length"], "byte_order": m["byte_order"],
                               "update_bit": m["update_bit"], "source": "arxml"}
                        key = (hop["kind"], hop.get("can_id"), hop.get("header_id"), hop.get("channel"),
                               str(hop.get("container")), hop["start_bit"])
                        if key not in seen:
                            seen.add(key)
                            hops.append(hop)
                    if not self._carriers(pdu):
                        notes.append(f"PDU {self._name(pdu)} (signal {self.signals[sig]['name']}) has no "
                                     "CAN frame / socket / container carrier in the ARXML")
        hops.sort(key=lambda h: (h["kind"] != "can", h.get("cluster") or ""))
        for i, h in enumerate(hops):
            h["hop"] = i
        return {"signal": signal, "isignals": sorted(self._name(s) for s in group),
                "hops": hops, "notes": sorted(set(notes))}


def describe_hop(h: dict) -> str:
    bus = "/".join(x for x in (h.get("cluster"), h.get("channel")) if x)
    on = f" on {bus}" if bus else ""
    if h["kind"] == "can":
        where = f"CAN 0x{h['can_id']:X}{' ext' if h.get('is_ext') else ''}{on}"
    elif h["kind"] == "pdu_over_ip":
        ports = ",".join(map(str, h.get("ports") or [])) or "any port"
        where = f"ETH PDU header 0x{h['header_id']:08X} ({ports}){on}"
    elif h["kind"] == "someip":
        where = f"SOME/IP 0x{h['service_id']:04X}.0x{h['method_id']:04X}"
    else:
        where = h["kind"]
    if h.get("container"):
        c = h["container"]
        cid = c.get("contained_header_id")
        where = f"contained id {cid:#x} in container {c.get('pdu')} via {where}" if cid is not None else \
            f"container {c.get('pdu')} via {where}"
    bits = f"bit {h['start_bit']} len {h['length']} {h['byte_order']}"
    ecus = ""
    if h.get("senders") or h.get("receivers"):
        ecus = f" [{','.join(h.get('senders') or ['?'])} -> {','.join(h.get('receivers') or ['?'])}]"
    pdu = f", PDU {h['pdu']}" if h.get("pdu") else ""
    return f"#{h.get('hop', '?')} {h.get('signal', '')} @ {where}{pdu} {bits}{ecus} ({h.get('source', 'arxml')})"
