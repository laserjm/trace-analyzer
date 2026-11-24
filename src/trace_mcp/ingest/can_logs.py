"""CAN ingest from Vector BLF/ASC (python-can) and ASAM MF4 bus logging (asammdf)."""

from __future__ import annotations

from pathlib import Path

import can
import numpy as np

from ..store import Batch, Store

COLUMNS = ["file_id", "ts", "channel", "can_id", "is_ext", "is_fd", "is_rx", "is_error", "dlc", "data"]


def _channel_name(ch) -> str:
    # python-can reports Vector channels 0-based; CANoe/CANalyzer show them 1-based.
    return f"CAN{ch + 1}" if isinstance(ch, int) else str(ch)


def ingest_vector(store: Store, path: Path, file_id: int, kind: str) -> dict:
    batch = Batch(store, "can_frames", COLUMNS)
    reader = can.BLFReader(str(path)) if kind == "blf" else can.ASCReader(str(path), relative_timestamp=False)
    skipped = 0
    for msg in reader:
        if msg.is_remote_frame:
            skipped += 1
            continue
        batch.add(file_id, msg.timestamp, _channel_name(msg.channel), msg.arbitration_id,
                  msg.is_extended_id, msg.is_fd, msg.is_rx, msg.is_error_frame, msg.dlc, bytes(msg.data))
    batch.flush()
    note = f"skipped {skipped} remote frames" if skipped else None
    if kind == "asc":
        note = ((note + "; ") if note else "") + (
            "ASC timestamps use the file's 'date' header; check alignment with set_time_offset")
    return {"n_records": batch.count, "ts_min": batch.ts_min if batch.count else None,
            "ts_max": batch.ts_max if batch.count else None, "note": note,
            "counts": {"can_frames": batch.count}}


def ingest_mf4(store: Store, path: Path, file_id: int) -> dict:
    """ASAM MDF4 bus logging (CAN_DataFrame / CAN_ErrorFrame groups).

    NOTE: written against the ASAM bus-logging standard but not yet verified with real
    logger files. Ethernet (ETH_Frame) groups and plain measurement channels are listed
    in the note but not ingested yet.
    """
    from asammdf import MDF

    batch = Batch(store, "can_frames", COLUMNS)
    other_groups: set[str] = set()
    with MDF(str(path)) as mdf:
        t0 = mdf.header.start_time.timestamp()
        for gi, group in enumerate(mdf.groups):
            names = {ch.name for ch in group.channels}
            for prefix, is_err in (("CAN_DataFrame", False), ("CAN_ErrorFrame", True)):
                if f"{prefix}.ID" not in names:
                    continue

                def get(field):
                    name = f"{prefix}.{field}"
                    return mdf.get(name, group=gi, raw=True).samples if name in names else None

                id_sig = mdf.get(f"{prefix}.ID", group=gi, raw=True)
                ts = id_sig.timestamps + t0
                ids = id_sig.samples.astype(np.uint64)
                ide = get("IDE")
                data = get("DataBytes")
                dlen = get("DataLength")
                dlc = get("DLC")
                bus = get("BusChannel")
                edl = get("EDL")
                direction = get("Dir")
                for i in range(len(ts)):
                    raw_id = int(ids[i])
                    ext = bool(ide[i]) if ide is not None else bool(raw_id & 0x80000000)
                    n = int(dlen[i]) if dlen is not None else (int(dlc[i]) if dlc is not None else 0)
                    payload = bytes(np.asarray(data[i], dtype=np.uint8)[:n]) if data is not None else b""
                    batch.add(file_id, float(ts[i]),
                              f"CAN{int(bus[i])}" if bus is not None else "CAN?",
                              raw_id & 0x1FFFFFFF, ext, bool(edl[i]) if edl is not None else False,
                              not bool(direction[i]) if direction is not None else True,
                              is_err, int(dlc[i]) if dlc is not None else n, payload)
            if not any(n.startswith("CAN_") for n in names):
                other_groups.update(n.split(".")[0] for n in names if n.endswith(("Frame", "Frame.ID")))
    batch.flush()
    note = f"not ingested: {', '.join(sorted(other_groups))}" if other_groups else None
    return {"n_records": batch.count, "ts_min": batch.ts_min if batch.count else None,
            "ts_max": batch.ts_max if batch.count else None, "note": note,
            "counts": {"can_frames": batch.count}}
