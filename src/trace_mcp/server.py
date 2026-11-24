"""MCP server: the tools the agent (Copilot CLI, Claude Code, ...) uses on trace cases.

Conventions every tool follows:
  * times in and out are *case time*: seconds since the earliest timestamp of the case
  * outputs are bounded (limits, downsampling) so the agent never receives raw dumps
  * errors come back as text the agent can act on
"""

from __future__ import annotations

import json
import threading
from datetime import datetime

from mcp.server.mcpserver import Image, MCPServer

from . import analysis, tracing
from .arxml import SystemModel, describe_hop
from .ingest import ingest_case as _ingest
from .store import IMAGE_EXTS, Store, cases_root, get_case

INSTRUCTIONS = """Trace analysis tools for automotive E/E traces (CAN, SOME/IP, SoAd PDUs, DoIP, DLT).
Start with case_overview. Times are seconds since case start (t=0 = earliest timestamp).
Use detectors (cycle_analysis, events_around) and trace_signal before raw SQL.
Cite file, bus, id and t= for every finding and record findings with add_finding."""

mcp = MCPServer("trace-tools", instructions=INSTRUCTIONS)

_models: dict[str, tuple[tuple, SystemModel]] = {}
_models_lock = threading.Lock()


def _store(case: str) -> Store:
    return Store.for_case(get_case(case))


def _model(case: str) -> SystemModel:
    c = get_case(case)
    files = c.arxml_files()
    if not files:
        raise ValueError(f"No *.arxml files in case '{case}'. Put them into cases/{case}/arxml/.")
    key = tuple((str(f), f.stat().st_mtime) for f in files)
    with _models_lock:
        if case not in _models or _models[case][0] != key:
            _models[case] = (key, SystemModel(files))
        return _models[case][1]


def _hops(case: str, signal: str | None, extra_hops: list[dict] | None, hop_ids: list[int] | None) -> list[dict]:
    hops = _model(case).routes(signal)["hops"] if signal else []
    if hop_ids:
        hops = [h for h in hops if h["hop"] in hop_ids]
    for i, h in enumerate(extra_hops or []):
        h = dict(h)
        h.setdefault("hop", 100 + i)
        h.setdefault("source", "manual")
        h.setdefault("signal", signal or h.get("label", "manual"))
        h.setdefault("byte_order", "little")
        for k in ("can_id", "header_id", "service_id", "method_id"):
            if isinstance(h.get(k), str):
                h[k] = int(h[k], 0)
        hops.append(h)
    return hops


# ------------------------------------------------------------------------------------
# Orientation
# ------------------------------------------------------------------------------------
@mcp.tool()
def list_cases() -> str:
    """List analysis cases (folders under the cases directory) and whether they are ingested."""
    root = cases_root()
    if not root.exists():
        return f"Cases directory {root} does not exist."
    lines = []
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        ingested = (d / "db" / "trace.duckdb").exists()
        n_raw = sum(1 for p in (d / "raw").rglob("*") if p.is_file()) if (d / "raw").exists() else 0
        lines.append(f"- {d.name}: {n_raw} raw files, {'ingested' if ingested else 'NOT ingested'}")
    return "\n".join(lines) or "(no cases)"


@mcp.tool()
def ingest_case(case: str, force: bool = False) -> str:
    """Parse all trace files in cases/<case>/raw into the case database. Unchanged files are
    skipped unless force=True. Run this before any other analysis tool."""
    reports = _ingest(get_case(case), force=force)
    return json.dumps(reports, indent=1, default=str)


@mcp.tool()
def case_overview(case: str) -> str:
    """Files, time ranges, record counts, buses/channels, top message ids, screenshots, ARXML
    and case notes. Start every investigation here."""
    c = get_case(case)
    s = _store(case)
    t0 = s.case_t0()
    if t0 is None:
        return "Case has no ingested data. Run ingest_case first."
    out = [f"# Case {case}", f"t=0 is {datetime.fromtimestamp(t0).isoformat()} (local time of logger clock), "
           f"end t={s.case_end() - t0:.3f}s", "", "## Files"]
    rows = s.q("SELECT file_id, path, kind, n_records, ts_min + ts_offset - ?, ts_max + ts_offset - ?, "
               "ts_offset, note FROM files ORDER BY file_id", [t0, t0])
    out.append(analysis.table(["id", "path", "kind", "records", "start_t", "end_t", "offset_s", "note"], rows))
    out += ["", "## Record counts"]
    for t in ("can_frames", "eth_packets", "someip", "someip_sd", "pdu_over_ip", "doip", "dlt"):
        n = s.q1(f"SELECT count(*) FROM {t}")
        if n:
            out.append(f"- {t}: {n}")
    can = s.q("SELECT channel, count(*), count(DISTINCT can_id), sum(is_error::INT) FROM v_can_frames "
              "GROUP BY 1 ORDER BY 1")
    if can:
        out += ["", "## CAN channels", analysis.table(["channel", "frames", "ids", "error_frames"], can)]
    eth = s.q("SELECT iface, vlan, count(*), count(DISTINCT src_ip) FROM v_eth_packets GROUP BY 1, 2 ORDER BY 3 DESC")
    if eth:
        out += ["", "## Ethernet interfaces", analysis.table(["iface", "vlan", "packets", "src_ips"], eth)]
    svc = s.q("SELECT printf('0x%04X', service_id), count(*), count(DISTINCT method_id), "
              "string_agg(DISTINCT src_ip, ',') FROM v_someip GROUP BY service_id ORDER BY 2 DESC LIMIT 15")
    if svc:
        out += ["", "## SOME/IP services (top 15)", analysis.table(["service", "msgs", "methods", "senders"], svc)]
    dlt = s.q("SELECT ecu, apid, count(*), sum((level <= 3)::INT) FROM v_dlt GROUP BY 1, 2 ORDER BY 4 DESC, 3 DESC LIMIT 15")
    if dlt:
        out += ["", "## DLT (top 15 ecu/app by warnings)", analysis.table(["ecu", "apid", "msgs", "warn+"], dlt)]
    shots = sorted(p.name for p in c.root.rglob("*") if p.suffix.lower() in IMAGE_EXTS)
    out += ["", f"## Screenshots: {', '.join(shots) if shots else 'none'}"]
    out.append(f"## ARXML: {', '.join(p.name for p in c.arxml_files()) or 'none'}")
    cfg = c.config()
    if cfg:
        out += ["## case.json", json.dumps(cfg, indent=1)]
    if c.findings_path.exists():
        n = c.findings_path.read_text().count("\n## ")
        out.append(f"## findings.md: {n} recorded findings (read the file to continue where you left off)")
    return "\n".join(out)


@mcp.tool()
def set_time_offset(case: str, file_id: int, offset_s: float) -> str:
    """Shift all timestamps of one file by offset_s seconds (clock alignment between loggers).
    Applies to every later query. Use when the same event appears at different times in two files."""
    s = _store(case)
    with s.lock:
        s.con.execute("UPDATE files SET ts_offset = ? WHERE file_id = ?", [offset_s, file_id])
    return f"file {file_id}: offset set to {offset_s} s"


@mcp.tool()
def set_channel_name(case: str, log_channel: str, arxml_name: str) -> str:
    """Map a log channel (e.g. 'CAN1' from BLF/ASC) to an ARXML cluster or physical-channel
    name so trace_signal only reads the right bus. Stored in case.json."""
    c = get_case(case)
    cfg = c.config()
    cfg.setdefault("channel_map", {})[log_channel] = arxml_name
    c.save_config(cfg)
    return f"{log_channel} -> {arxml_name}"


# ------------------------------------------------------------------------------------
# System description
# ------------------------------------------------------------------------------------
@mcp.tool()
def find_signal(case: str, pattern: str, limit: int = 30) -> str:
    """Search I-SIGNAL / SYSTEM-SIGNAL names in the case's ARXML (regex, case-insensitive)."""
    hits = _model(case).find_signals(pattern, limit)
    if not hits:
        return "no match"
    return analysis.table(["isignal", "system_signal", "pdus", "path"],
                          [(h["isignal"], h["system_signal"], ", ".join(h["pdus"]), h["path"]) for h in hits])


@mcp.tool()
def signal_routes(case: str, signal: str) -> str:
    """All wire locations ("hops") of a signal from ARXML: CAN frames, Ethernet PDUs
    (socket header ids), container PDUs, gateway mappings, sender/receiver ECUs.
    Hop numbers are used by trace_signal and signal_values."""
    r = _model(case).routes(signal)
    lines = [f"Signal {signal}: related I-SIGNALs {r.get('isignals', [])}"]
    lines += [describe_hop(h) for h in r["hops"]] or ["(no hops)"]
    if r["notes"]:
        lines += ["", "Notes:"] + [f"- {n}" for n in r["notes"]]
    return "\n".join(lines)


# ------------------------------------------------------------------------------------
# Signal tracing
# ------------------------------------------------------------------------------------
@mcp.tool()
def trace_signal(case: str, signal: str | None = None, t_start: float | None = None,
                 t_end: float | None = None, hops: list[int] | None = None,
                 extra_hops: list[dict] | None = None, reference_hop: int | None = None,
                 max_latency_ms: float = 500.0) -> str:
    """Follow a signal across every hop (CAN -> gateway -> Ethernet ...) and report per hop:
    presence, period, gaps, STOPPED/STUCK status, and whether it follows the reference hop's
    value changes within max_latency_ms (first missed change = where the chain breaks).

    hops: restrict to these ARXML hop numbers (see signal_routes).
    extra_hops: manual hop definitions when ARXML is missing/wrong, e.g.
      {"kind":"can","can_id":"0x1A0","start_bit":8,"length":4,"byte_order":"little","log_channels":["CAN1"]}
      {"kind":"pdu_over_ip","header_id":"0x1001","start_bit":0,"length":4,"byte_order":"big"}
      {"kind":"someip","service_id":"0x1234","method_id":"0x8001","start_bit":0,"length":8,
       "byte_order":"big","payload_offset_bytes":0}
      Optional: "container": {"header_type":"SHORT-HEADER","contained_header_id":161}, "update_bit": n.
    """
    hop_list = _hops(case, signal, extra_hops, hops)
    if not hop_list:
        return "No hops: signal not found in ARXML and no extra_hops given. Try find_signal."
    return tracing.trace_signal(_store(case), hop_list, t_start, t_end, reference_hop, max_latency_ms / 1000)


@mcp.tool()
def signal_values(case: str, signal: str | None = None, hop: int = 0, t_start: float | None = None,
                  t_end: float | None = None, changes_only: bool = True, max_rows: int = 100,
                  extra_hop: dict | None = None) -> str:
    """Decoded raw values of one hop of a signal (value changes by default, downsampled to
    max_rows). Use to inspect behaviour around a break found by trace_signal, or to check a
    manual bit layout via extra_hop."""
    hop_list = _hops(case, signal, [extra_hop] if extra_hop else None, None)
    h = next((x for x in hop_list if x["hop"] == hop), hop_list[-1] if extra_hop else None)
    if h is None:
        return f"hop {hop} not found; see signal_routes"
    return tracing.signal_values(_store(case), h, t_start, t_end, max_rows, changes_only)


# ------------------------------------------------------------------------------------
# Detectors and timeline
# ------------------------------------------------------------------------------------
@mcp.tool()
def cycle_analysis(case: str, kind: str = "can", t_start: float | None = None, t_end: float | None = None,
                   gap_factor: float = 3.0, min_count: int = 5, match: str | None = None, top: int = 30) -> str:
    """Cyclic-message health: median cycle, gaps > gap_factor x cycle, messages that STOPPED or
    STARTED LATE inside the window. kind: can | someip (notifications) | pdu_over_ip.
    match: regex on the message key (e.g. '0x1A0' or '10.0.0.5')."""
    if kind not in analysis.CYCLE_KEYS:
        return f"kind must be one of {list(analysis.CYCLE_KEYS)}"
    return analysis.cycle_analysis(_store(case), kind, t_start, t_end, gap_factor, min_count, match, top)


@mcp.tool()
def events_around(case: str, t: float, window_s: float = 1.0, include_info: bool = False, limit: int = 80) -> str:
    """Merged timeline around case time t from all sources: CAN error frames, SOME/IP-SD
    (offers, subscriptions, NACKs, stop-offers), SOME/IP errors, DLT warnings/errors, DoIP."""
    return analysis.events_around(_store(case), t, window_s, include_info, limit)


@mcp.tool()
def someip_sd_timeline(case: str, service_id: str | None = None, t_start: float | None = None,
                       t_end: float | None = None, limit: int = 100) -> str:
    """SOME/IP service discovery entries over time (optionally for one service id, e.g. '0x1234').
    Look for missing OfferService renewals, StopSubscribe, SubscribeEventgroupNack."""
    s = _store(case)
    lo, hi = s.window(t_start, t_end)
    t0 = s.case_t0() or 0.0
    sql = ("SELECT ts - ?, src_ip, dst_ip, entry, printf('0x%04X', service_id), instance_id, major_version, ttl, "
           "printf('0x%04X', eventgroup_id), endpoints FROM v_someip_sd WHERE ts BETWEEN ? AND ?")
    params: list = [t0, lo, hi]
    if service_id:
        sql += " AND service_id = ?"
        params.append(int(service_id, 0))
    rows = s.q(sql + " ORDER BY ts LIMIT ?", params + [limit])
    return analysis.table(["t", "src", "dst", "entry", "service", "inst", "major", "ttl", "eventgroup", "endpoints"], rows)


@mcp.tool()
def dlt_search(case: str, pattern: str, ecu: str | None = None, apid: str | None = None,
               max_level: int | None = None, t_start: float | None = None, t_end: float | None = None,
               limit: int = 50) -> str:
    """Regex search (case-insensitive) in DLT log text. max_level: 1 fatal, 2 error, 3 warn, 4 info, 5 debug."""
    s = _store(case)
    lo, hi = s.window(t_start, t_end)
    t0 = s.case_t0() or 0.0
    sql = ("SELECT ts - ?, ecu, apid, ctid, level, text FROM v_dlt WHERE regexp_matches(text, ?, 'i') "
           "AND ts BETWEEN ? AND ?")
    params: list = [t0, pattern, lo, hi]
    for col, val in (("ecu", ecu), ("apid", apid)):
        if val:
            sql += f" AND {col} = ?"
            params.append(val)
    if max_level is not None:
        sql += " AND level <= ?"
        params.append(max_level)
    total = s.q1(f"SELECT count(*) FROM ({sql})", params)
    rows = s.q(sql + " ORDER BY ts LIMIT ?", params + [limit])
    return f"{total} matches (showing {len(rows)})\n" + analysis.table(["t", "ecu", "apid", "ctid", "level", "text"], rows)


@mcp.tool()
def sql(case: str, query: str, limit: int = 100) -> str:
    """Read-only DuckDB SELECT on the case database for questions the other tools don't cover.
    Prefer the v_* views (clock offsets applied): v_can_frames, v_eth_packets, v_someip,
    v_someip_sd, v_pdu_over_ip, v_doip, v_dlt, plus table files. Timestamps are absolute;
    use case_t(ts) to convert to case time. Blobs: data/payload (use get_byte(data, i), hex(data))."""
    s = _store(case)
    with s.lock:
        stmts = s.con.extract_statements(query)
        if len(stmts) != 1 or stmts[0].type.name != "SELECT":
            return "Only a single SELECT statement is allowed."
        cur = s.con.execute(query)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchmany(limit + 1)
    more = len(rows) > limit
    return analysis.table(cols, rows[:limit]) + (f"\n(more than {limit} rows - aggregate or narrow the query)" if more else "")


# ------------------------------------------------------------------------------------
# Screenshots and findings
# ------------------------------------------------------------------------------------
@mcp.tool()
def view_screenshot(case: str, name: str) -> Image | str:
    """Return a screenshot from the case folder so you can look at it (CANoe windows, scope
    captures, HMI/cluster photos). Read timestamps visible in it to align with trace time."""
    c = get_case(case)
    matches = [p for p in c.root.rglob("*") if p.name == name and p.suffix.lower() in IMAGE_EXTS]
    if not matches:
        return f"No screenshot named {name}. See case_overview for the list."
    return Image(path=matches[0])


@mcp.tool()
def add_finding(case: str, title: str, status: str, evidence: list[str], next_steps: str = "") -> str:
    """Append a finding to the case notebook findings.md. status: hypothesis | confirmed | rejected.
    evidence: one line each with file/bus/id/t= and the tool call that showed it."""
    if status not in ("hypothesis", "confirmed", "rejected"):
        return "status must be hypothesis | confirmed | rejected"
    c = get_case(case)
    entry = [f"\n## [{status.upper()}] {title}", f"_recorded {datetime.now().isoformat(timespec='seconds')}_", ""]
    entry += [f"- {e}" for e in evidence]
    if next_steps:
        entry += ["", f"Next: {next_steps}"]
    if not c.findings_path.exists():
        c.findings_path.write_text(f"# Findings - case {case}\n")
    with c.findings_path.open("a") as f:
        f.write("\n".join(entry) + "\n")
    return f"recorded in {c.findings_path}"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
