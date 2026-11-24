"""Case layout and the DuckDB store that every tool queries.

A case is a folder:

    cases/<case-id>/
        raw/          trace files (BLF, ASC, MF4, PCAP/PCAPNG, DLT) - any subfolder depth
        arxml/        ARXML system descriptions
        screenshots/  PNG/JPG
        db/           generated: trace.duckdb, arxml cache
        case.json     optional: channel names, notes
        findings.md   the agent's notebook

All timestamps in the store are absolute (epoch seconds, as written by the logger).
Per-file clock corrections live in files.ts_offset and are applied by the v_* views.
Tools talk in *case time*: seconds since the earliest corrected timestamp of the case.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

import duckdb
import pyarrow as pa

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    file_id INTEGER PRIMARY KEY, path VARCHAR, kind VARCHAR, size_bytes BIGINT,
    ts_min DOUBLE, ts_max DOUBLE, n_records BIGINT, ts_offset DOUBLE DEFAULT 0,
    note VARCHAR
);
CREATE TABLE IF NOT EXISTS can_frames (
    file_id INTEGER, ts DOUBLE, channel VARCHAR, can_id UBIGINT, is_ext BOOLEAN,
    is_fd BOOLEAN, is_rx BOOLEAN, is_error BOOLEAN, dlc INTEGER, data BLOB
);
CREATE TABLE IF NOT EXISTS eth_packets (
    file_id INTEGER, ts DOUBLE, iface VARCHAR, vlan INTEGER, src_ip VARCHAR, dst_ip VARCHAR,
    proto VARCHAR, src_port INTEGER, dst_port INTEGER, length INTEGER, payload BLOB
);
CREATE TABLE IF NOT EXISTS someip (
    file_id INTEGER, ts DOUBLE, iface VARCHAR, vlan INTEGER, src_ip VARCHAR, dst_ip VARCHAR,
    proto VARCHAR, src_port INTEGER, dst_port INTEGER, service_id INTEGER, method_id INTEGER,
    client_id INTEGER, session_id INTEGER, iface_version INTEGER, msg_type INTEGER,
    return_code INTEGER, payload BLOB
);
CREATE TABLE IF NOT EXISTS someip_sd (
    file_id INTEGER, ts DOUBLE, src_ip VARCHAR, dst_ip VARCHAR, entry VARCHAR,
    service_id INTEGER, instance_id INTEGER, major_version INTEGER, ttl INTEGER,
    eventgroup_id INTEGER, endpoints VARCHAR
);
CREATE TABLE IF NOT EXISTS pdu_over_ip (
    file_id INTEGER, ts DOUBLE, src_ip VARCHAR, dst_ip VARCHAR, proto VARCHAR,
    src_port INTEGER, dst_port INTEGER, header_id UBIGINT, length INTEGER, data BLOB
);
CREATE TABLE IF NOT EXISTS doip (
    file_id INTEGER, ts DOUBLE, src_ip VARCHAR, dst_ip VARCHAR, payload_type INTEGER,
    source_addr INTEGER, target_addr INTEGER, uds VARCHAR
);
CREATE TABLE IF NOT EXISTS dlt (
    file_id INTEGER, ts DOUBLE, ecu VARCHAR, apid VARCHAR, ctid VARCHAR, msg_type VARCHAR,
    level INTEGER, text VARCHAR
);
CREATE TABLE IF NOT EXISTS meta (key VARCHAR PRIMARY KEY, value VARCHAR);
"""

# Views apply per-file clock offsets. Everything outside ingest reads the views.
VIEWS = {
    name: f"CREATE OR REPLACE VIEW v_{name} AS SELECT t.* REPLACE (t.ts + f.ts_offset AS ts) "
    f"FROM {name} t JOIN files f USING (file_id)"
    for name in ("can_frames", "eth_packets", "someip", "someip_sd", "pdu_over_ip", "doip", "dlt")
}

TRACE_EXTS = {
    ".blf": "blf", ".asc": "asc", ".mf4": "mf4", ".mdf": "mf4",
    ".pcap": "pcap", ".pcapng": "pcap", ".cap": "pcap", ".dlt": "dlt",
}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}


def cases_root() -> Path:
    return Path(os.environ.get("TRACE_CASES_DIR", "cases")).resolve()


@dataclass
class Case:
    case_id: str
    root: Path

    @property
    def raw_dir(self) -> Path:
        return self.root / "raw"

    @property
    def arxml_dir(self) -> Path:
        return self.root / "arxml"

    @property
    def screenshot_dir(self) -> Path:
        return self.root / "screenshots"

    @property
    def db_dir(self) -> Path:
        return self.root / "db"

    @property
    def findings_path(self) -> Path:
        return self.root / "findings.md"

    def config(self) -> dict:
        p = self.root / "case.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def save_config(self, cfg: dict) -> None:
        (self.root / "case.json").write_text(json.dumps(cfg, indent=2) + "\n")

    def trace_files(self) -> list[tuple[Path, str]]:
        out = []
        for p in sorted(self.raw_dir.rglob("*")):
            kind = TRACE_EXTS.get(p.suffix.lower())
            if p.is_file() and kind:
                out.append((p, kind))
        return out

    def arxml_files(self) -> list[Path]:
        return sorted(p for p in self.root.rglob("*.arxml") if p.is_file())


def get_case(case_id: str) -> Case:
    root = (cases_root() / case_id).resolve()
    if cases_root() not in root.parents or not root.is_dir():
        raise ValueError(f"Unknown case '{case_id}'. Use list_cases to see available cases.")
    return Case(case_id, root)


class Store:
    """One DuckDB connection per case, guarded by a lock (tools may run in threads)."""

    _open: dict[str, "Store"] = {}
    _open_lock = threading.Lock()

    def __init__(self, case: Case):
        self.case = case
        case.db_dir.mkdir(exist_ok=True)
        # No file access from SQL: the agent's `sql` tool must not read or write outside the DB.
        self.con = duckdb.connect(str(case.db_dir / "trace.duckdb"),
                                  config={"enable_external_access": False})
        self.lock = threading.RLock()
        self.con.execute(SCHEMA)
        for sql in VIEWS.values():
            self.con.execute(sql)
        self.con.execute("CREATE OR REPLACE MACRO case_t(ts) AS "
                         "ts - (SELECT min(ts_min + ts_offset) FROM files)")

    @classmethod
    def for_case(cls, case: Case) -> "Store":
        with cls._open_lock:
            if case.case_id not in cls._open:
                cls._open[case.case_id] = cls(case)
            return cls._open[case.case_id]

    # --- helpers -----------------------------------------------------------------
    def q(self, sql: str, params: list | tuple = ()) -> list[tuple]:
        with self.lock:
            return self.con.execute(sql, params).fetchall()

    def q1(self, sql: str, params: list | tuple = ()):
        rows = self.q(sql, params)
        return rows[0][0] if rows else None

    def insert(self, table: str, columns: dict[str, list]) -> None:
        if not columns or not next(iter(columns.values())):
            return
        tbl = pa.table(columns)
        with self.lock:
            self.con.register("_batch", tbl)
            cols = ", ".join(columns)
            self.con.execute(f"INSERT INTO {table} ({cols}) SELECT {cols} FROM _batch")
            self.con.unregister("_batch")

    def set_meta(self, key: str, value) -> None:
        with self.lock:
            self.con.execute(
                "INSERT OR REPLACE INTO meta VALUES (?, ?)", [key, json.dumps(value)]
            )

    def get_meta(self, key: str, default=None):
        v = self.q1("SELECT value FROM meta WHERE key = ?", [key])
        return json.loads(v) if v is not None else default

    def case_t0(self) -> float | None:
        """Earliest corrected timestamp over all files: the zero of case time."""
        return self.q1("SELECT min(ts_min + ts_offset) FROM files WHERE ts_min IS NOT NULL")

    def window(self, t_start: float | None, t_end: float | None) -> tuple[float, float]:
        """Convert case-time bounds to absolute bounds."""
        t0 = self.case_t0() or 0.0
        lo = t0 + t_start if t_start is not None else float("-inf")
        hi = t0 + t_end if t_end is not None else float("inf")
        return lo, hi

    def case_end(self) -> float:
        return self.q1("SELECT max(ts_max + ts_offset) FROM files") or 0.0


class Batch:
    """Column-wise buffer that flushes into the store every N rows."""

    def __init__(self, store: Store, table: str, columns: list[str], size: int = 200_000):
        self.store, self.table, self.columns, self.size = store, table, columns, size
        self.buf: dict[str, list] = {c: [] for c in columns}
        self.count = 0
        self.ts_min = float("inf")
        self.ts_max = float("-inf")

    def add(self, *values) -> None:
        for c, v in zip(self.columns, values):
            self.buf[c].append(v)
        self.count += 1
        if "ts" in self.buf:
            ts = self.buf["ts"][-1]
            if ts < self.ts_min:
                self.ts_min = ts
            if ts > self.ts_max:
                self.ts_max = ts
        if len(self.buf[self.columns[0]]) >= self.size:
            self.flush()

    def flush(self) -> None:
        self.store.insert(self.table, self.buf)
        self.buf = {c: [] for c in self.columns}
