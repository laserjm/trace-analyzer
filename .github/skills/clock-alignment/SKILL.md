---
name: clock-alignment
description: Align timestamps of trace files recorded by different loggers or ECUs (BLF vs PCAP vs DLT vs screenshots) before correlating events across them. Use whenever a case has more than one trace file or a screenshot with a visible time.
---

# Clock alignment

Each file keeps its own logger clock. `case_overview` lists each file's start and end in
case time and its current `offset_s`.

## Find a common event

Use something that appears in both files:
- The **same CAN frame** recorded by two loggers (or by the CAN tap in a PCAPNG):
  `sql` on `v_can_frames` for one id, grouped by `file_id`, and compare the first
  timestamps of an identical payload sequence.
- A gateway-routed message: CAN frame -> Ethernet PDU. Only use this when the gateway
  latency is known (it is usually a few ms); `trace_signal` reports the latency per hop.
- An ECU reset: the last DLT message before the restart against the bus traffic gap.
- For screenshots, the clock shown in the tool window (CANoe trace window, scope).

## Apply

`set_time_offset(file_id, offset_s)`: the value is **added** to that file's timestamps.
Then repeat the comparison to confirm that the files now agree within about 1 ms
(network loggers) or about 10 ms (DLT over ECU clock).

Record the offset and how you found it with `add_finding`, so the next session doesn't
repeat the work.
