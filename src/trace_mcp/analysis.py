"""Deterministic detectors and timeline queries. They find candidates cheaply so the
model only reasons about a short list."""

from __future__ import annotations

from .store import Store

CYCLE_KEYS = {
    "can": ("v_can_frames", "channel || ' 0x' || printf('%X', can_id)", "NOT is_error"),
    "someip": ("v_someip", "src_ip || ' ' || printf('0x%04X.0x%04X', service_id, method_id)", "msg_type = 2"),
    "pdu_over_ip": ("v_pdu_over_ip", "src_ip || ':' || src_port || ' 0x' || printf('%08X', header_id)", "TRUE"),
}


def fmt_val(v) -> str:
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return b[:32].hex(" ") + (f" …(+{len(b) - 32}B)" if len(b) > 32 else "")
    if isinstance(v, float):
        return f"{v:.6f}"
    return "" if v is None else str(v)


def table(cols: list[str], rows: list[tuple], max_cell: int = 120) -> str:
    if not rows:
        return "(no rows)"
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(fmt_val(v)[:max_cell].replace("|", "\\|") for v in r) + " |")
    return "\n".join(out)


def cycle_analysis(store: Store, kind: str, t_start, t_end, gap_factor: float, min_count: int,
                   key_filter: str | None, top: int) -> str:
    view, key, where = CYCLE_KEYS[kind]
    lo, hi = store.window(t_start, t_end)
    t0 = store.case_t0() or 0.0
    w_lo = max(lo, t0)
    w_hi = min(hi, store.case_end())
    sql = f"""
    WITH x AS (
        SELECT {key} AS k, ts, ts - lag(ts) OVER (PARTITION BY {key} ORDER BY ts) AS dt
        FROM {view} WHERE {where} AND ts BETWEEN ? AND ?
    ), s AS (
        SELECT k, count(*) AS n, median(dt) AS med, max(dt) AS maxdt, arg_max(ts - dt, dt) AS gap_at,
               min(ts) AS first_ts, max(ts) AS last_ts
        FROM x GROUP BY k HAVING count(*) >= ?
    )
    SELECT s.k, s.n, s.med * 1000, s.maxdt * 1000,
           (SELECT count(*) FROM x WHERE x.k = s.k AND x.dt > ? * s.med) AS n_gaps,
           s.gap_at - ?, s.first_ts - ?, s.last_ts - ?,
           CASE WHEN ? - s.last_ts > ? * s.med AND ? - s.last_ts > 0.2 THEN 'STOPPED'
                WHEN s.first_ts - ? > ? * s.med AND s.first_ts - ? > 0.2 THEN 'STARTED LATE'
                WHEN s.maxdt > ? * s.med THEN 'GAPS' ELSE '' END AS flag
    FROM s
    WHERE ? IS NULL OR regexp_matches(s.k, ?, 'i')
    ORDER BY (flag = 'STOPPED') DESC, (flag = 'STARTED LATE') DESC, s.maxdt / nullif(s.med, 0) DESC
    LIMIT ?
    """
    rows = store.q(sql, [lo, hi, min_count, gap_factor, t0, t0, t0, w_hi, gap_factor, w_hi, w_lo,
                         gap_factor, w_lo, gap_factor, key_filter, key_filter or "", top])
    cols = ["message", "count", "median_cycle_ms", "max_gap_ms", f"gaps>{gap_factor}x", "max_gap_at_t",
            "first_t", "last_t", "flag"]
    return (f"Cycle analysis ({kind}), window end t={w_hi - t0:.3f}s. Sorted: stopped, started late, "
            f"worst gap ratio.\n" + table(cols, rows))


def events_around(store: Store, t: float, window: float, include_info: bool, limit: int) -> str:
    t0 = store.case_t0() or 0.0
    lo, hi = t0 + t - window, t0 + t + window
    level = 6 if include_info else 3
    sql = f"""
    SELECT ts - ? AS t, src, text FROM (
        SELECT ts, 'CAN ' || channel AS src, 'ERROR FRAME' AS text FROM v_can_frames
            WHERE is_error AND ts BETWEEN ? AND ?
        UNION ALL
        SELECT ts, 'SOME/IP-SD ' || src_ip, entry || ' service 0x' || printf('%04X', service_id)
            || ' inst ' || instance_id || coalesce(' eg 0x' || printf('%04X', eventgroup_id), '')
            || ' ttl ' || ttl || ' -> ' || dst_ip || coalesce(' ' || endpoints, '')
            FROM v_someip_sd WHERE ts BETWEEN ? AND ?
        UNION ALL
        SELECT ts, 'SOME/IP ' || src_ip, 'type 0x' || printf('%02X', msg_type) || ' rc 0x'
            || printf('%02X', return_code) || ' ' || printf('0x%04X.0x%04X', service_id, method_id)
            FROM v_someip WHERE (msg_type IN (129, 193) OR return_code <> 0) AND ts BETWEEN ? AND ?
        UNION ALL
        SELECT ts, 'DLT ' || ecu || '/' || apid || '/' || ctid,
               '[' || coalesce(CAST(level AS VARCHAR), msg_type) || '] ' || text
            FROM v_dlt WHERE (level IS NULL OR level <= {level}) AND ts BETWEEN ? AND ?
        UNION ALL
        SELECT ts, 'DoIP ' || src_ip, 'type 0x' || printf('%04X', payload_type) || ' SA '
            || coalesce(printf('0x%04X', source_addr), '-') || ' TA ' || coalesce(printf('0x%04X', target_addr), '-')
            || ' ' || uds FROM v_doip WHERE ts BETWEEN ? AND ?
    ) ORDER BY ts LIMIT ?
    """
    rows = store.q(sql, [t0] + [lo, hi] * 5 + [limit])
    return (f"Events between t={t - window:.3f}s and t={t + window:.3f}s "
            f"(DLT levels <= {level}; 1=fatal 2=error 3=warn 4=info):\n" + table(["t", "source", "event"], rows))
