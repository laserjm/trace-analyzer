import struct
import subprocess
import sys
from pathlib import Path

import pytest

from trace_mcp.decode import extract, unpack_container
from trace_mcp.ingest.pcap import parse_sd, parse_soad, parse_someip

ROOT = Path(__file__).resolve().parents[1]


# --- pure decoders -----------------------------------------------------------------
def test_extract_little_endian():
    data = bytes([0x00, 0x0B, 0, 0, 0, 0, 0, 0])
    assert extract(data, 8, 4, "little") == 0xB


def test_extract_big_endian_msb_start():
    data = bytes([0, 0, 0x03, 0xE8, 0, 0, 0, 0])  # 1000 in bytes 2..3, MSB at bit 23
    assert extract(data, 23, 16, "big") == 1000


def test_extract_out_of_range_returns_none():
    assert extract(b"\x00", 4, 8, "little") is None


def test_container_short_header():
    c = (0xA1).to_bytes(3, "big") + b"\x02" + b"\x11\x22" + (0xA2).to_bytes(3, "big") + b"\x01" + b"\x33"
    assert unpack_container(c, "SHORT-HEADER") == [(0xA1, b"\x11\x22"), (0xA2, b"\x33")]


def test_someip_tiling_and_rejects_garbage():
    msg = struct.pack(">HHIHHBBBB", 0x1234, 0x8001, 10, 0, 1, 1, 1, 0x02, 0) + b"\xab\xcd"
    assert parse_someip(msg + msg)[1][:2] == (0x1234, 0x8001)
    assert parse_someip(msg[:-1]) is None
    assert parse_someip(b"\x00" * 20) is None


def test_soad_requires_exact_tiling():
    assert parse_soad(struct.pack(">II", 0x1001, 2) + b"\x01\x02") == [(0x1001, b"\x01\x02")]
    assert parse_soad(struct.pack(">II", 0x1001, 3) + b"\x01\x02") is None


def test_sd_nack_and_endpoint():
    entry = struct.pack(">BBBBHHB", 0x06, 0, 0, 0x10, 0x1234, 1, 1) + (3).to_bytes(3, "big") + struct.pack(">BBH", 0, 0, 7)
    opt = struct.pack(">HBB", 9, 4, 0) + bytes([10, 0, 0, 30]) + struct.pack(">BBH", 0, 0x11, 40001)
    body = b"\xc0\0\0\0" + struct.pack(">I", 16) + entry + struct.pack(">I", len(opt)) + opt
    assert parse_sd(body) == [("SubscribeEventgroup", 0x1234, 1, 1, 3, 7, "10.0.0.30:40001/udp")]


# --- end to end on the synthetic demo case ------------------------------------------
@pytest.fixture(scope="module")
def demo(tmp_path_factory, monkeypatch_module):
    cases = tmp_path_factory.mktemp("cases")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "make_demo_case.py"), str(cases)], check=True)
    monkeypatch_module.setenv("TRACE_CASES_DIR", str(cases))
    from trace_mcp import server
    server.ingest_case("demo")
    return server


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


def test_routes_follow_system_signal_into_container(demo):
    out = demo.signal_routes("demo", "DoorLockState")
    assert "CAN 0x1A0" in out and "contained id 0xa1" in out and "[CGW -> HPC]" in out


def test_trace_finds_break_at_30s(demo):
    out = demo.trace_signal("demo", "DoorLockState")
    assert "STOPPED: last value at t=29.982s" in out
    assert "WITHOUT this contained PDU" in out
    assert "FIRST MISSED change -> 3 at t=30.000s" in out


def test_detectors(demo):
    assert "| CAN1 0x2B0 |" in demo.cycle_analysis("demo", "can").split("\n")[3]
    assert "STOPPED" in demo.cycle_analysis("demo", "someip")
    ev = demo.events_around("demo", 30.0, 0.1)
    assert "SubscribeEventgroupNack" in ev and "E2E check failed" in ev


def test_sql_is_read_only(demo):
    assert "Only a single SELECT" in demo.sql("demo", "DELETE FROM files")
    assert "Only a single SELECT" in demo.sql("demo", "SELECT 1; DROP TABLE files")
    with pytest.raises(Exception):
        demo.sql("demo", "SELECT * FROM read_text('/etc/hosts')")
