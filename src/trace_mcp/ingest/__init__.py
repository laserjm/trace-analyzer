"""Ingest dispatcher: raw trace files -> DuckDB tables."""

from __future__ import annotations

import time

from ..store import Case, Store
from .can_logs import ingest_mf4, ingest_vector
from .dlt import ingest_dlt
from .pcap import ingest_pcap

DATA_TABLES = ("can_frames", "eth_packets", "someip", "someip_sd", "pdu_over_ip", "doip", "dlt")


def ingest_case(case: Case, force: bool = False) -> list[dict]:
    """Ingest every trace file below raw/. Already ingested, unchanged files are skipped
    unless force=True. Returns one report per file."""
    store = Store.for_case(case)
    reports = []
    for path, kind in case.trace_files():
        rel = str(path.relative_to(case.root))
        size = path.stat().st_size
        existing = store.q("SELECT file_id, size_bytes, ts_offset FROM files WHERE path = ?", [rel])
        offset = 0.0
        if existing:
            file_id, old_size, offset = existing[0]
            if old_size == size and not force:
                reports.append({"file": rel, "status": "already ingested", "file_id": file_id})
                continue
            with store.lock:
                for t in DATA_TABLES:
                    store.con.execute(f"DELETE FROM {t} WHERE file_id = ?", [file_id])
                store.con.execute("DELETE FROM files WHERE file_id = ?", [file_id])
        else:
            file_id = (store.q1("SELECT max(file_id) FROM files") or 0) + 1
        started = time.time()
        try:
            if kind in ("blf", "asc"):
                info = ingest_vector(store, path, file_id, kind)
            elif kind == "mf4":
                info = ingest_mf4(store, path, file_id)
            elif kind == "pcap":
                info = ingest_pcap(store, path, file_id)
            else:
                info = ingest_dlt(store, path, file_id)
        except Exception as exc:  # report and continue with the next file
            reports.append({"file": rel, "status": f"FAILED: {type(exc).__name__}: {exc}"})
            continue
        with store.lock:
            store.con.execute(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [file_id, rel, kind, size, info["ts_min"], info["ts_max"], info["n_records"],
                 offset, info.get("note")],
            )
        reports.append({"file": rel, "file_id": file_id, "kind": kind, "status": "ingested",
                        "seconds": round(time.time() - started, 1), **info.get("counts", {}),
                        **({"note": info["note"]} if info.get("note") else {})})
    return reports
