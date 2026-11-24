"""Generate a synthetic demo case: a CAN signal gatewayed into an Ethernet container PDU
that disappears from the Ethernet side at t=30 s.

    uv run python scripts/make_demo_case.py [cases_dir]

Contents of cases/demo:
  raw/body_can.blf       CAN1: BCM_Status 0x1A0 (20 ms) with DoorLockState + VehicleSpeed,
                         Wiper_Status 0x2B0 (100 ms) which stops at t=45 s
  raw/backbone.pcapng    if "ETH_Backbone" (VLAN 10): SoAd PDU 0x1001 carrying container GW_Container_1
                         (contained 0xA1 = BCM_Status_PDU_ETH, 0xA2 = Other_PDU_ETH); 0xA1 is missing
                         from t=30 s. SOME/IP-SD offers/subscriptions for service 0x1234, a NACK at
                         t=30 s, and event 0x1234.0x8001 which stops after the NACK.
                         if "CAN_tap" (SocketCAN): 0x3C0 every 100 ms
  raw/cgw.dlt            gateway log with a warning at t=30 s
  arxml/system.arxml     system description for all of the above
"""

from __future__ import annotations

import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

import can
import dpkt

T0 = datetime(2026, 11, 20, 9, 0, 0, tzinfo=timezone.utc).timestamp()
DURATION = 60.0
BREAK_T = 30.0


def door_lock(t: float) -> int:
    return int(t // 2) % 4


def speed(t: float) -> int:
    return int(1000 + 500 * ((t % 20) / 20))


def bcm_status_payload(t: float) -> bytes:
    data = bytearray(8)
    data[1] = door_lock(t) & 0x0F                     # little endian, start bit 8, len 4
    v = speed(t)                                      # big endian, MSB at bit 23, len 16
    data[2], data[3] = v >> 8, v & 0xFF
    return bytes(data)


def bcm_status_eth_payload(t: float) -> bytes:
    data = bytearray(8)
    data[2] = door_lock(t) & 0x0F                     # little endian, start bit 16, len 4
    return bytes(data)


# ---------------------------------------------------------------------------------- CAN
def write_blf(path: Path) -> None:
    w = can.BLFWriter(str(path))
    n = int(DURATION / 0.02)
    for i in range(n):
        t = i * 0.02
        w.on_message_received(can.Message(timestamp=T0 + t, arbitration_id=0x1A0, is_extended_id=False,
                                          data=bcm_status_payload(t), channel=0))
        if i % 5 == 0 and t < 45.0:
            w.on_message_received(can.Message(timestamp=T0 + t + 0.003, arbitration_id=0x2B0,
                                              is_extended_id=False, data=bytes([i % 256, 0, 0, 0]), channel=0))
    w.stop()


# ---------------------------------------------------------------------------------- ETH
def udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes, vlan: int = 10) -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = 8 + len(payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=17, ttl=64, data=udp)
    ip.len = 20 + udp.ulen
    tci = struct.pack(">HHH", 0x8100, vlan, 0x0800)
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + tci + bytes(ip)


def someip(service: int, method: int, payload: bytes, mtype: int = 0x02, session: int = 1) -> bytes:
    return struct.pack(">HHIHHBBBB", service, method, 8 + len(payload), 0, session, 1, 1, mtype, 0) + payload


def sd_message(entries: list[bytes], options: list[bytes]) -> bytes:
    e = b"".join(entries)
    o = b"".join(options)
    body = b"\xc0\x00\x00\x00" + struct.pack(">I", len(e)) + e + struct.pack(">I", len(o)) + o
    return someip(0xFFFF, 0x8100, body)


def ipv4_option(ip: str, port: int) -> bytes:
    return struct.pack(">HBB", 9, 0x04, 0) + socket.inet_aton(ip) + struct.pack(">BBH", 0, 0x11, port)


def sd_entry(etype: int, service: int, ttl: int, eventgroup: int | None = None, nopt: int = 0x10) -> bytes:
    head = struct.pack(">BBBBHHB", etype, 0, 0, nopt, service, 1, 1) + ttl.to_bytes(3, "big")
    tail = struct.pack(">BBH", 0, 0, eventgroup) if eventgroup is not None else struct.pack(">I", 0)
    return head + tail


def pcapng_block(btype: int, body: bytes) -> bytes:
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    n = len(body) + 12
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def idb(linktype: int, name: str) -> bytes:
    nm = name.encode()
    opt = struct.pack("<HH", 2, len(nm)) + nm + b"\x00" * ((4 - len(nm) % 4) % 4)
    opt += struct.pack("<HHB3x", 9, 1, 6) + struct.pack("<HH", 0, 0)  # microsecond resolution
    return pcapng_block(1, struct.pack("<HHI", linktype, 0, 65535) + opt)


def epb(iface: int, ts: float, data: bytes) -> bytes:
    us = int(round(ts * 1e6))
    return pcapng_block(6, struct.pack("<IIIII", iface, us >> 32, us & 0xFFFFFFFF, len(data), len(data)) + data)


def write_pcapng(path: Path) -> None:
    packets: list[tuple[float, int, bytes]] = []
    n = int(DURATION / 0.02)
    for i in range(n):
        t = i * 0.02
        contained = b""
        if t < BREAK_T:
            contained += (0xA1).to_bytes(3, "big") + bytes([8]) + bcm_status_eth_payload(t)
        contained += (0xA2).to_bytes(3, "big") + bytes([4]) + bytes([1, 2, 3, i % 256])
        soad = struct.pack(">II", 0x1001, len(contained)) + contained
        packets.append((T0 + t + 0.002, 0, udp_frame("10.0.0.1", "10.0.0.20", 50001, 50002, soad)))
        if i % 5 == 0:  # SocketCAN frame on second interface
            frame = struct.pack(">IB3x", 0x3C0, 4) + bytes([0xAA, 0xBB, 0xCC, i % 256]) + b"\x00" * 4
            packets.append((T0 + t + 0.001, 1, frame))
    for s in range(int(DURATION)):
        t = float(s)
        packets.append((T0 + t + 0.5, 0, udp_frame("10.0.0.20", "224.244.224.245", 30490, 30490, sd_message(
            [sd_entry(0x01, 0x1234, 3)], [ipv4_option("10.0.0.20", 30501)]))))
        if s == 1:
            packets.append((T0 + t + 0.6, 0, udp_frame("10.0.0.30", "10.0.0.20", 30490, 30490, sd_message(
                [sd_entry(0x06, 0x1234, 3, eventgroup=0x0001)], [ipv4_option("10.0.0.30", 40001)]))))
            packets.append((T0 + t + 0.61, 0, udp_frame("10.0.0.20", "10.0.0.30", 30490, 30490, sd_message(
                [sd_entry(0x07, 0x1234, 3, eventgroup=0x0001, nopt=0)], []))))
    packets.append((T0 + BREAK_T + 0.01, 0, udp_frame("10.0.0.20", "10.0.0.30", 30490, 30490, sd_message(
        [sd_entry(0x07, 0x1234, 0, eventgroup=0x0001, nopt=0)], []))))
    for i in range(int(BREAK_T / 0.1)):
        t = 2.0 + i * 0.1
        if t < BREAK_T:
            packets.append((T0 + t, 0, udp_frame("10.0.0.20", "10.0.0.30", 30501, 40001,
                                                  someip(0x1234, 0x8001, struct.pack(">H", speed(t)), session=i + 1))))
    packets.sort(key=lambda p: p[0])
    shb = pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    with open(path, "wb") as f:
        f.write(shb + idb(1, "ETH_Backbone") + idb(227, "CAN_tap"))
        for ts, iface, data in packets:
            f.write(epb(iface, ts, data))


# ---------------------------------------------------------------------------------- DLT
def dlt_msg(ts: float, level: int, apid: str, ctid: str, text: str, count: int) -> bytes:
    arg = text.encode() + b"\x00"
    payload = struct.pack("<IH", 0x200, len(arg)) + arg
    ext = bytes([0x01 | (level << 4), 1]) + apid.encode().ljust(4, b"\x00") + ctid.encode().ljust(4, b"\x00")
    std_len = 4 + 4 + 4 + len(ext) + len(payload)
    std = struct.pack(">BBH", 0x35, count % 256, std_len) + b"CGW\x00" + struct.pack(">I", int((ts - T0 + 100.0) * 10000))  # ECU uptime
    storage = b"DLT\x01" + struct.pack("<Ii", int(ts), int(round((ts % 1) * 1e6))) + b"CGW\x00"
    return storage + std + ext + payload


def write_dlt(path: Path) -> None:
    msgs, c = [], 0
    for s in range(0, int(DURATION), 5):
        msgs.append((T0 + s + 0.1, 4, "PDUR", "RT", f"routing table active, {12 + (s // 5) % 2} paths"))
    msgs.append((T0 + BREAK_T - 0.004, 3, "PDUR", "RT",
                 "routing path BCM_Status_PDU -> GW_Container_1 disabled: E2E check failed (counter jump)"))
    msgs.append((T0 + BREAK_T + 0.012, 2, "SOAD", "SD", "eventgroup 0x0001 of service 0x1234: subscription rejected"))
    with open(path, "wb") as f:
        for ts, level, apid, ctid, text in sorted(msgs):
            f.write(dlt_msg(ts, level, apid, ctid, text, c))
            c += 1


# ---------------------------------------------------------------------------------- ARXML
ARXML = """<?xml version="1.0" encoding="UTF-8"?>
<AUTOSAR xmlns="http://autosar.org/schema/r4.0">
<AR-PACKAGES><AR-PACKAGE><SHORT-NAME>Demo</SHORT-NAME><AR-PACKAGES>
 <AR-PACKAGE><SHORT-NAME>SystemSignals</SHORT-NAME><ELEMENTS>
  <SYSTEM-SIGNAL><SHORT-NAME>DoorLockState_SYS</SHORT-NAME></SYSTEM-SIGNAL>
  <SYSTEM-SIGNAL><SHORT-NAME>VehicleSpeed_SYS</SHORT-NAME></SYSTEM-SIGNAL>
 </ELEMENTS></AR-PACKAGE>
 <AR-PACKAGE><SHORT-NAME>ISignals</SHORT-NAME><ELEMENTS>
  <I-SIGNAL><SHORT-NAME>DoorLockState</SHORT-NAME><LENGTH>4</LENGTH>
   <SYSTEM-SIGNAL-REF DEST="SYSTEM-SIGNAL">/Demo/SystemSignals/DoorLockState_SYS</SYSTEM-SIGNAL-REF></I-SIGNAL>
  <I-SIGNAL><SHORT-NAME>DoorLockState_ETH</SHORT-NAME><LENGTH>4</LENGTH>
   <SYSTEM-SIGNAL-REF DEST="SYSTEM-SIGNAL">/Demo/SystemSignals/DoorLockState_SYS</SYSTEM-SIGNAL-REF></I-SIGNAL>
  <I-SIGNAL><SHORT-NAME>VehicleSpeed</SHORT-NAME><LENGTH>16</LENGTH>
   <SYSTEM-SIGNAL-REF DEST="SYSTEM-SIGNAL">/Demo/SystemSignals/VehicleSpeed_SYS</SYSTEM-SIGNAL-REF></I-SIGNAL>
 </ELEMENTS></AR-PACKAGE>
 <AR-PACKAGE><SHORT-NAME>Pdus</SHORT-NAME><ELEMENTS>
  <I-SIGNAL-I-PDU><SHORT-NAME>BCM_Status_PDU</SHORT-NAME><LENGTH>8</LENGTH><I-SIGNAL-TO-PDU-MAPPINGS>
   <I-SIGNAL-TO-I-PDU-MAPPING><SHORT-NAME>M_DoorLockState</SHORT-NAME>
    <I-SIGNAL-REF DEST="I-SIGNAL">/Demo/ISignals/DoorLockState</I-SIGNAL-REF>
    <PACKING-BYTE-ORDER>MOST-SIGNIFICANT-BYTE-LAST</PACKING-BYTE-ORDER><START-POSITION>8</START-POSITION>
   </I-SIGNAL-TO-I-PDU-MAPPING>
   <I-SIGNAL-TO-I-PDU-MAPPING><SHORT-NAME>M_VehicleSpeed</SHORT-NAME>
    <I-SIGNAL-REF DEST="I-SIGNAL">/Demo/ISignals/VehicleSpeed</I-SIGNAL-REF>
    <PACKING-BYTE-ORDER>MOST-SIGNIFICANT-BYTE-FIRST</PACKING-BYTE-ORDER><START-POSITION>23</START-POSITION>
   </I-SIGNAL-TO-I-PDU-MAPPING>
  </I-SIGNAL-TO-PDU-MAPPINGS></I-SIGNAL-I-PDU>
  <I-SIGNAL-I-PDU><SHORT-NAME>BCM_Status_PDU_ETH</SHORT-NAME><LENGTH>8</LENGTH>
   <CONTAINED-I-PDU-PROPS><HEADER-ID-SHORT-HEADER>161</HEADER-ID-SHORT-HEADER></CONTAINED-I-PDU-PROPS>
   <I-SIGNAL-TO-PDU-MAPPINGS><I-SIGNAL-TO-I-PDU-MAPPING><SHORT-NAME>M_DoorLockState_ETH</SHORT-NAME>
    <I-SIGNAL-REF DEST="I-SIGNAL">/Demo/ISignals/DoorLockState_ETH</I-SIGNAL-REF>
    <PACKING-BYTE-ORDER>MOST-SIGNIFICANT-BYTE-LAST</PACKING-BYTE-ORDER><START-POSITION>16</START-POSITION>
   </I-SIGNAL-TO-I-PDU-MAPPING></I-SIGNAL-TO-PDU-MAPPINGS></I-SIGNAL-I-PDU>
  <I-SIGNAL-I-PDU><SHORT-NAME>Other_PDU_ETH</SHORT-NAME><LENGTH>4</LENGTH>
   <CONTAINED-I-PDU-PROPS><HEADER-ID-SHORT-HEADER>162</HEADER-ID-SHORT-HEADER></CONTAINED-I-PDU-PROPS></I-SIGNAL-I-PDU>
  <CONTAINER-I-PDU><SHORT-NAME>GW_Container_1</SHORT-NAME><LENGTH>64</LENGTH><HEADER-TYPE>SHORT-HEADER</HEADER-TYPE>
   <CONTAINED-PDU-TRIGGERING-REFS>
    <CONTAINED-PDU-TRIGGERING-REF DEST="PDU-TRIGGERING">/Demo/Clusters/Backbone_ETH/Backbone_Channel/PT_BCM_Status_ETH</CONTAINED-PDU-TRIGGERING-REF>
    <CONTAINED-PDU-TRIGGERING-REF DEST="PDU-TRIGGERING">/Demo/Clusters/Backbone_ETH/Backbone_Channel/PT_Other_ETH</CONTAINED-PDU-TRIGGERING-REF>
   </CONTAINED-PDU-TRIGGERING-REFS></CONTAINER-I-PDU>
 </ELEMENTS></AR-PACKAGE>
 <AR-PACKAGE><SHORT-NAME>Frames</SHORT-NAME><ELEMENTS>
  <CAN-FRAME><SHORT-NAME>BCM_Status</SHORT-NAME><FRAME-LENGTH>8</FRAME-LENGTH><PDU-TO-FRAME-MAPPINGS>
   <PDU-TO-FRAME-MAPPING><SHORT-NAME>PM_BCM_Status</SHORT-NAME>
    <PACKING-BYTE-ORDER>MOST-SIGNIFICANT-BYTE-LAST</PACKING-BYTE-ORDER>
    <PDU-REF DEST="I-SIGNAL-I-PDU">/Demo/Pdus/BCM_Status_PDU</PDU-REF><START-POSITION>0</START-POSITION>
   </PDU-TO-FRAME-MAPPING></PDU-TO-FRAME-MAPPINGS></CAN-FRAME>
 </ELEMENTS></AR-PACKAGE>
 <AR-PACKAGE><SHORT-NAME>Ecus</SHORT-NAME><ELEMENTS>
  <ECU-INSTANCE><SHORT-NAME>BCM</SHORT-NAME><CONNECTORS><CAN-COMMUNICATION-CONNECTOR><SHORT-NAME>Conn_Body</SHORT-NAME>
   <ECU-COMM-PORT-INSTANCES><FRAME-PORT><SHORT-NAME>FP_BCM_Status</SHORT-NAME>
    <COMMUNICATION-DIRECTION>OUT</COMMUNICATION-DIRECTION></FRAME-PORT></ECU-COMM-PORT-INSTANCES>
  </CAN-COMMUNICATION-CONNECTOR></CONNECTORS></ECU-INSTANCE>
  <ECU-INSTANCE><SHORT-NAME>CGW</SHORT-NAME><CONNECTORS>
   <CAN-COMMUNICATION-CONNECTOR><SHORT-NAME>Conn_Body</SHORT-NAME><ECU-COMM-PORT-INSTANCES>
    <FRAME-PORT><SHORT-NAME>FP_BCM_Status</SHORT-NAME><COMMUNICATION-DIRECTION>IN</COMMUNICATION-DIRECTION></FRAME-PORT>
   </ECU-COMM-PORT-INSTANCES></CAN-COMMUNICATION-CONNECTOR>
   <ETHERNET-COMMUNICATION-CONNECTOR><SHORT-NAME>Conn_ETH</SHORT-NAME><ECU-COMM-PORT-INSTANCES>
    <I-PDU-PORT><SHORT-NAME>IPP_Container</SHORT-NAME><COMMUNICATION-DIRECTION>OUT</COMMUNICATION-DIRECTION></I-PDU-PORT>
   </ECU-COMM-PORT-INSTANCES></ETHERNET-COMMUNICATION-CONNECTOR>
  </CONNECTORS></ECU-INSTANCE>
  <ECU-INSTANCE><SHORT-NAME>HPC</SHORT-NAME><CONNECTORS>
   <ETHERNET-COMMUNICATION-CONNECTOR><SHORT-NAME>Conn_ETH</SHORT-NAME><ECU-COMM-PORT-INSTANCES>
    <I-PDU-PORT><SHORT-NAME>IPP_Container</SHORT-NAME><COMMUNICATION-DIRECTION>IN</COMMUNICATION-DIRECTION></I-PDU-PORT>
   </ECU-COMM-PORT-INSTANCES></ETHERNET-COMMUNICATION-CONNECTOR>
  </CONNECTORS></ECU-INSTANCE>
  <GATEWAY><SHORT-NAME>CGW_Gateway</SHORT-NAME><ECU-REF DEST="ECU-INSTANCE">/Demo/Ecus/CGW</ECU-REF>
   <SIGNAL-MAPPINGS><I-SIGNAL-MAPPING>
    <SOURCE-SIGNAL-REF DEST="I-SIGNAL-TRIGGERING">/Demo/Clusters/Body_CAN/Body_CAN_Channel/ST_DoorLockState</SOURCE-SIGNAL-REF>
    <TARGET-SIGNAL-REF DEST="I-SIGNAL-TRIGGERING">/Demo/Clusters/Backbone_ETH/Backbone_Channel/ST_DoorLockState_ETH</TARGET-SIGNAL-REF>
   </I-SIGNAL-MAPPING></SIGNAL-MAPPINGS></GATEWAY>
 </ELEMENTS></AR-PACKAGE>
 <AR-PACKAGE><SHORT-NAME>Clusters</SHORT-NAME><ELEMENTS>
  <CAN-CLUSTER><SHORT-NAME>Body_CAN</SHORT-NAME><CAN-CLUSTER-VARIANTS><CAN-CLUSTER-CONDITIONAL><PHYSICAL-CHANNELS>
   <CAN-PHYSICAL-CHANNEL><SHORT-NAME>Body_CAN_Channel</SHORT-NAME>
    <FRAME-TRIGGERINGS><CAN-FRAME-TRIGGERING><SHORT-NAME>FT_BCM_Status</SHORT-NAME>
     <FRAME-PORT-REFS>
      <FRAME-PORT-REF DEST="FRAME-PORT">/Demo/Ecus/BCM/Conn_Body/FP_BCM_Status</FRAME-PORT-REF>
      <FRAME-PORT-REF DEST="FRAME-PORT">/Demo/Ecus/CGW/Conn_Body/FP_BCM_Status</FRAME-PORT-REF>
     </FRAME-PORT-REFS>
     <FRAME-REF DEST="CAN-FRAME">/Demo/Frames/BCM_Status</FRAME-REF>
     <CAN-ADDRESSING-MODE>STANDARD</CAN-ADDRESSING-MODE><IDENTIFIER>416</IDENTIFIER>
    </CAN-FRAME-TRIGGERING></FRAME-TRIGGERINGS>
    <I-SIGNAL-TRIGGERINGS><I-SIGNAL-TRIGGERING><SHORT-NAME>ST_DoorLockState</SHORT-NAME>
     <I-SIGNAL-REF DEST="I-SIGNAL">/Demo/ISignals/DoorLockState</I-SIGNAL-REF></I-SIGNAL-TRIGGERING></I-SIGNAL-TRIGGERINGS>
    <PDU-TRIGGERINGS><PDU-TRIGGERING><SHORT-NAME>PT_BCM_Status</SHORT-NAME>
     <I-PDU-REF DEST="I-SIGNAL-I-PDU">/Demo/Pdus/BCM_Status_PDU</I-PDU-REF></PDU-TRIGGERING></PDU-TRIGGERINGS>
   </CAN-PHYSICAL-CHANNEL>
  </PHYSICAL-CHANNELS></CAN-CLUSTER-CONDITIONAL></CAN-CLUSTER-VARIANTS></CAN-CLUSTER>
  <ETHERNET-CLUSTER><SHORT-NAME>Backbone_ETH</SHORT-NAME><ETHERNET-CLUSTER-VARIANTS><ETHERNET-CLUSTER-CONDITIONAL><PHYSICAL-CHANNELS>
   <ETHERNET-PHYSICAL-CHANNEL><SHORT-NAME>Backbone_Channel</SHORT-NAME>
    <I-SIGNAL-TRIGGERINGS><I-SIGNAL-TRIGGERING><SHORT-NAME>ST_DoorLockState_ETH</SHORT-NAME>
     <I-SIGNAL-REF DEST="I-SIGNAL">/Demo/ISignals/DoorLockState_ETH</I-SIGNAL-REF></I-SIGNAL-TRIGGERING></I-SIGNAL-TRIGGERINGS>
    <NETWORK-ENDPOINTS>
     <NETWORK-ENDPOINT><SHORT-NAME>NE_CGW</SHORT-NAME><NETWORK-ENDPOINT-ADDRESSES><IPV-4-CONFIGURATION>
      <IPV-4-ADDRESS>10.0.0.1</IPV-4-ADDRESS></IPV-4-CONFIGURATION></NETWORK-ENDPOINT-ADDRESSES></NETWORK-ENDPOINT>
     <NETWORK-ENDPOINT><SHORT-NAME>NE_HPC</SHORT-NAME><NETWORK-ENDPOINT-ADDRESSES><IPV-4-CONFIGURATION>
      <IPV-4-ADDRESS>10.0.0.20</IPV-4-ADDRESS></IPV-4-CONFIGURATION></NETWORK-ENDPOINT-ADDRESSES></NETWORK-ENDPOINT>
    </NETWORK-ENDPOINTS>
    <PDU-TRIGGERINGS>
     <PDU-TRIGGERING><SHORT-NAME>PT_GW_Container_1</SHORT-NAME>
      <I-PDU-PORT-REFS>
       <I-PDU-PORT-REF DEST="I-PDU-PORT">/Demo/Ecus/CGW/Conn_ETH/IPP_Container</I-PDU-PORT-REF>
       <I-PDU-PORT-REF DEST="I-PDU-PORT">/Demo/Ecus/HPC/Conn_ETH/IPP_Container</I-PDU-PORT-REF>
      </I-PDU-PORT-REFS>
      <I-PDU-REF DEST="CONTAINER-I-PDU">/Demo/Pdus/GW_Container_1</I-PDU-REF></PDU-TRIGGERING>
     <PDU-TRIGGERING><SHORT-NAME>PT_BCM_Status_ETH</SHORT-NAME>
      <I-PDU-REF DEST="I-SIGNAL-I-PDU">/Demo/Pdus/BCM_Status_PDU_ETH</I-PDU-REF></PDU-TRIGGERING>
     <PDU-TRIGGERING><SHORT-NAME>PT_Other_ETH</SHORT-NAME>
      <I-PDU-REF DEST="I-SIGNAL-I-PDU">/Demo/Pdus/Other_PDU_ETH</I-PDU-REF></PDU-TRIGGERING>
    </PDU-TRIGGERINGS>
    <SO-AD-CONFIG>
     <CONNECTION-BUNDLES><SOCKET-CONNECTION-BUNDLE><SHORT-NAME>Bundle_CGW_HPC</SHORT-NAME>
      <BUNDLED-CONNECTIONS><SOCKET-CONNECTION>
       <CLIENT-PORT-REF DEST="SOCKET-ADDRESS">/Demo/Clusters/Backbone_ETH/Backbone_Channel/SA_CGW</CLIENT-PORT-REF>
       <PDUS><SOCKET-CONNECTION-IPDU-IDENTIFIER><HEADER-ID>4097</HEADER-ID>
        <PDU-TRIGGERING-REF DEST="PDU-TRIGGERING">/Demo/Clusters/Backbone_ETH/Backbone_Channel/PT_GW_Container_1</PDU-TRIGGERING-REF>
       </SOCKET-CONNECTION-IPDU-IDENTIFIER></PDUS>
      </SOCKET-CONNECTION></BUNDLED-CONNECTIONS>
      <SERVER-PORT-REF DEST="SOCKET-ADDRESS">/Demo/Clusters/Backbone_ETH/Backbone_Channel/SA_HPC</SERVER-PORT-REF>
     </SOCKET-CONNECTION-BUNDLE></CONNECTION-BUNDLES>
     <SOCKET-ADDRESSS>
      <SOCKET-ADDRESS><SHORT-NAME>SA_CGW</SHORT-NAME><APPLICATION-ENDPOINT><SHORT-NAME>AE_CGW</SHORT-NAME>
       <NETWORK-ENDPOINT-REF DEST="NETWORK-ENDPOINT">/Demo/Clusters/Backbone_ETH/Backbone_Channel/NE_CGW</NETWORK-ENDPOINT-REF>
       <TP-CONFIGURATION><UDP-TP><UDP-TP-PORT><PORT-NUMBER>50001</PORT-NUMBER></UDP-TP-PORT></UDP-TP></TP-CONFIGURATION>
      </APPLICATION-ENDPOINT></SOCKET-ADDRESS>
      <SOCKET-ADDRESS><SHORT-NAME>SA_HPC</SHORT-NAME><APPLICATION-ENDPOINT><SHORT-NAME>AE_HPC</SHORT-NAME>
       <NETWORK-ENDPOINT-REF DEST="NETWORK-ENDPOINT">/Demo/Clusters/Backbone_ETH/Backbone_Channel/NE_HPC</NETWORK-ENDPOINT-REF>
       <TP-CONFIGURATION><UDP-TP><UDP-TP-PORT><PORT-NUMBER>50002</PORT-NUMBER></UDP-TP-PORT></UDP-TP></TP-CONFIGURATION>
      </APPLICATION-ENDPOINT></SOCKET-ADDRESS>
     </SOCKET-ADDRESSS>
    </SO-AD-CONFIG>
   </ETHERNET-PHYSICAL-CHANNEL>
  </PHYSICAL-CHANNELS></ETHERNET-CLUSTER-CONDITIONAL></ETHERNET-CLUSTER-VARIANTS></ETHERNET-CLUSTER>
 </ELEMENTS></AR-PACKAGE>
</AR-PACKAGES></AR-PACKAGE></AR-PACKAGES>
</AUTOSAR>
"""


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "cases") / "demo"
    for sub in ("raw", "arxml", "screenshots"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    write_blf(root / "raw" / "body_can.blf")
    write_pcapng(root / "raw" / "backbone.pcapng")
    write_dlt(root / "raw" / "cgw.dlt")
    (root / "arxml" / "system.arxml").write_text(ARXML)
    (root / "case.json").write_text('{\n  "ticket": "DEMO-1: DoorLockState not received by HPC",\n'
                                    '  "channel_map": {"CAN1": "Body_CAN"}\n}\n')
    print(f"demo case written to {root}")


if __name__ == "__main__":
    main()
