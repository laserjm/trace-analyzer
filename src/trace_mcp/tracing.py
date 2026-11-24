"""Follow one signal across all of its hops and find where the chain breaks."""

from __future__ import annotations

import bisect
import statistics
from collections import Counter

from .arxml import describe_hop
from .decode import bit_set, extract, unpack_container
from .store import Store


def channel_filter(store: Store, hop: dict) -> list[str] | None:
    """Log channels (e.g. 'CAN1') mapped to the hop's ARXML cluster/channel in case.json."""
    cmap = store.case.config().get("channel_map", {})
    names = {hop.get("cluster"), hop.get("channel")} - {None}
    chans = [log for log, arxml in cmap.items() if arxml in names]
    return chans or None


def carrier_messages(store: Store, hop: dict, lo: float, hi: float) -> tuple[list[tuple[float, bytes]], str]:
    """(ts, pdu_bytes) of every wire message that carries the hop's PDU (or its container)."""
    kind = hop["kind"]
    if kind == "can":
        sql = ("SELECT ts, data, channel FROM v_can_frames WHERE can_id = ? AND is_ext = ? "
               "AND NOT is_error AND ts BETWEEN ? AND ?")
        params: list = [hop["can_id"], bool(hop.get("is_ext")), lo, hi]
        chans = hop.get("log_channels") or channel_filter(store, hop)
        if chans:
            sql += f" AND channel IN ({','.join('?' * len(chans))})"
            params += chans
        rows = store.q(sql + " ORDER BY ts", params)
        seen = Counter(r[2] for r in rows)
        info = f"log channels {dict(seen)}" + ("" if chans else " (unfiltered - map channels with set_channel_name)")
        return [(r[0], r[1]) for r in rows], info
    if kind == "pdu_over_ip":
        sql = "SELECT ts, data, dst_port FROM v_pdu_over_ip WHERE header_id = ? AND ts BETWEEN ? AND ?"
        params = [hop["header_id"], lo, hi]
        if hop.get("ports"):
            sql += f" AND (dst_port IN ({','.join('?' * len(hop['ports']))}) OR src_port IN ({','.join('?' * len(hop['ports']))}))"
            params += list(hop["ports"]) * 2
        rows = store.q(sql + " ORDER BY ts", params)
        if rows:
            return [(r[0], r[1]) for r in rows], "SoAd PDU header match"
        # Same id may be a SOME/IP message id (service << 16 | method)
        rows = store.q("SELECT ts, payload FROM v_someip WHERE service_id = ? AND method_id = ? "
                       "AND ts BETWEEN ? AND ? ORDER BY ts",
                       [hop["header_id"] >> 16, hop["header_id"] & 0xFFFF, lo, hi])
        return [(r[0], r[1]) for r in rows], ("matched as SOME/IP message id; ASSUMPTION: PDU bytes = "
                                              "SOME/IP payload" if rows else "no PDU / SOME/IP message with this id")
    if kind == "someip":
        rows = store.q("SELECT ts, payload FROM v_someip WHERE service_id = ? AND method_id = ? "
                       "AND ts BETWEEN ? AND ? ORDER BY ts", [hop["service_id"], hop["method_id"], lo, hi])
        return [(r[0], r[1]) for r in rows], "SOME/IP payload"
    raise ValueError(f"unknown hop kind {kind}")


def hop_series(store: Store, hop: dict, lo: float, hi: float) -> dict:
    """Decode the hop's signal values: list of (ts, value|None) plus carrier info."""
    msgs, info = carrier_messages(store, hop, lo, hi)
    offset_bytes = (hop.get("pdu_offset_bits") or 0) // 8 + (hop.get("payload_offset_bytes") or 0)
    container = hop.get("container")
    series, carriers, not_updated, undecodable = [], 0, 0, 0
    for ts, data in msgs:
        data = bytes(data)
        if container:
            hits = [d for cid, d in unpack_container(data, container.get("header_type", "SHORT-HEADER"))
                    if cid == container.get("contained_header_id")]
            if not hits:
                continue  # container present, contained PDU absent
            pdu = hits[0]
        else:
            pdu = data[offset_bytes:]
            if hop.get("pdu_length"):
                pdu = pdu[:hop["pdu_length"]]
        carriers += 1
        if hop.get("update_bit") is not None and bit_set(pdu, hop["update_bit"]) is False:
            not_updated += 1
            continue
        v = extract(pdu, hop["start_bit"], hop["length"] or 0, hop["byte_order"])
        if v is None:
            undecodable += 1
            continue
        series.append((ts, v))
    return {"series": series, "carrier_msgs": len(msgs), "pdu_present": carriers,
            "last_carrier_ts": msgs[-1][0] if msgs else None,
            "not_updated": not_updated, "undecodable": undecodable, "carrier_info": info}


def changes(series: list[tuple[float, int]]) -> list[tuple[float, int]]:
    out, last = [], object()
    for ts, v in series:
        if v != last:
            out.append((ts, v))
            last = v
    return out


def _period(ts: list[float]) -> float | None:
    if len(ts) < 3:
        return None
    return statistics.median(b - a for a, b in zip(ts, ts[1:]))


def follow(ref: list[tuple[float, int]], other: list[tuple[float, int]], max_latency: float) -> dict:
    """For each value change at the reference hop, does the other hop show the new value
    within max_latency? Returns counts, latencies and the first missed change."""
    o_ts = [t for t, _ in other]
    matched, missed, lat = 0, [], []
    for t, v in changes(ref)[1:]:  # first entry is the initial value, not a change
        i = bisect.bisect_left(o_ts, t)
        hit = None
        while i < len(other) and other[i][0] <= t + max_latency:
            if other[i][1] == v:
                hit = other[i][0]
                break
            i += 1
        if hit is None:
            missed.append((t, v))
        else:
            matched += 1
            lat.append(hit - t)
    return {"matched": matched, "missed": missed,
            "latency_median_ms": round(statistics.median(lat) * 1000, 2) if lat else None,
            "latency_max_ms": round(max(lat) * 1000, 2) if lat else None}


def trace_signal(store: Store, hops: list[dict], t_start, t_end, reference_hop: int | None,
                 max_latency: float) -> str:
    lo, hi = store.window(t_start, t_end)
    t0 = store.case_t0() or 0.0
    end = min(hi, store.case_end())
    rel = lambda ts: f"t={ts - t0:.3f}s"  # noqa: E731

    results = []
    for h in hops:
        r = hop_series(store, h, lo, hi)
        s = r["series"]
        ts = [t for t, _ in s]
        period = _period(ts)
        ch = changes(s)
        r.update(hop=h, period=period, changes=ch)
        if not r["carrier_msgs"]:
            status = "NOT FOUND in window (no carrier message at all)"
        elif not r["pdu_present"]:
            status = "carrier present but PDU never contained"
        elif not s:
            status = "PDU present but signal never decodable/updated"
        else:
            gap_limit = max(3 * (period or 0), 0.5)
            status = "present until end of window"
            if end - ts[-1] > gap_limit:
                status = f"STOPPED: last value at {rel(ts[-1])} ({end - ts[-1]:.2f}s before window end)"
                if r["last_carrier_ts"] - ts[-1] > gap_limit:
                    what = "container keeps arriving WITHOUT this contained PDU" if h.get("container") \
                        else "carrier message keeps arriving but the signal is no longer decodable/updated"
                    status += f"; {what} until {rel(r['last_carrier_ts'])}"
            gaps = [(a, b - a) for a, b in zip(ts, ts[1:]) if b - a > gap_limit]
            if gaps:
                g = max(gaps, key=lambda x: x[1])
                status += f"; {len(gaps)} gap(s) > {gap_limit:.2f}s, longest {g[1]:.2f}s at {rel(g[0])}"
        r["status"] = status
        results.append(r)

    # reference = requested hop, else the one with data that changes earliest
    candidates = [r for r in results if len(r["changes"]) > 1]
    if reference_hop is not None:
        ref = next((r for r in results if r["hop"].get("hop") == reference_hop), None)
    else:
        ref = min(candidates, key=lambda r: r["changes"][1][0], default=None)

    lines = [f"Window {rel(lo if lo > float('-inf') else t0)} .. {rel(end)}; max latency {max_latency * 1000:.0f} ms", ""]
    for r in results:
        h, s = r["hop"], r["series"]
        lines.append(describe_hop(h))
        lines.append(f"   carriers: {r['carrier_msgs']} msgs ({r['carrier_info']}); PDU present {r['pdu_present']}; "
                     f"values {len(s)}; not-updated {r['not_updated']}; undecodable {r['undecodable']}")
        if s:
            top = Counter(v for _, v in s).most_common(4)
            lines.append(f"   first {rel(s[0][0])}, last {rel(s[-1][0])}, period "
                         f"{(r['period'] or 0) * 1000:.1f} ms, changes {len(r['changes']) - 1}, "
                         f"last change {rel(r['changes'][-1][0])}, last value {s[-1][1]}, "
                         f"most common {top}")
        lines.append(f"   status: {r['status']}")
        if ref is not None and r is not ref and s:
            f = follow(ref["series"], s, max_latency)
            msg = (f"   follows hop #{ref['hop'].get('hop')}: {f['matched']} of {f['matched'] + len(f['missed'])} "
                   f"changes within latency (median {f['latency_median_ms']} ms, max {f['latency_max_ms']} ms)")
            if f["missed"]:
                first_t, first_v = f["missed"][0]
                msg += f"; FIRST MISSED change -> {first_v} at {rel(first_t)}"
                ref_after = [c for c in ref["changes"] if c[0] > r["changes"][-1][0]]
                if ref_after and r["status"].startswith("present"):
                    msg += f"; STUCK at {s[-1][1]} since {rel(r['changes'][-1][0])} while reference kept changing"
            lines.append(msg)
        lines.append("")
    if ref is not None:
        lines.append(f"Reference hop: #{ref['hop'].get('hop')} (earliest change)" if reference_hop is None
                     else f"Reference hop: #{reference_hop}")
    else:
        lines.append("No hop with value changes: follow analysis not possible (check bit layout / window).")
    return "\n".join(lines)


def signal_values(store: Store, hop: dict, t_start, t_end, max_rows: int, changes_only: bool) -> str:
    lo, hi = store.window(t_start, t_end)
    t0 = store.case_t0() or 0.0
    r = hop_series(store, hop, lo, hi)
    s = changes(r["series"]) if changes_only else r["series"]
    lines = [describe_hop(hop), f"{len(s)} {'changes' if changes_only else 'samples'} "
             f"(carrier msgs {r['carrier_msgs']}, {r['carrier_info']})"]
    if len(s) > max_rows:
        step = len(s) / max_rows
        s = [s[int(i * step)] for i in range(max_rows)]
        lines.append(f"(downsampled to {max_rows} rows)")
    lines += [f"t={t - t0:.6f}  {v}  (0x{v:X})" for t, v in s]
    return "\n".join(lines)
