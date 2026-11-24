---
name: signal-path-tracing
description: Method for following a signal across buses (CAN -> gateway -> Ethernet/SOME/IP and back) and finding where and why it disappears, gets stuck, or arrives with a wrong value. Use when a receiver does not see a signal that a sender transmits, or when values differ between buses.
---

# Signal path tracing

Goal: find the **first hop** where the signal deviates from its source, and explain why.

## 1. Establish the route

1. `find_signal` with part of the name, then `signal_routes` with the exact name.
   The route groups all I-SIGNALs that share a SYSTEM-SIGNAL plus gateway mappings, so the
   Ethernet-side signal may have a different name.
2. Check each hop: bus, id, PDU, bit position, byte order, sender -> receiver ECUs.
   Read the `Notes` - a PDU without a carrier means the ARXML route is incomplete.
3. If a CAN hop shows "unfiltered" log channels, map the log channel to the ARXML cluster
   with `set_channel_name` (e.g. `CAN1` -> `Body_CAN`). The same CAN id may exist on
   several buses.

## 2. Trace

1. `trace_signal` over the whole case first, then narrow `t_start`/`t_end` around the
   break.
2. Read the result per hop:
   - **NOT FOUND**: no carrier message at all. Is the bus/interface in the capture?
     Is the id right? Use `cycle_analysis` with `match` to look for the id.
   - **carrier present but PDU never contained**: the container/SoAd message arrives but
     without this PDU. Look at the gateway's routing conditions.
   - **STOPPED ... container keeps arriving WITHOUT this contained PDU**: the gateway
     stopped routing this PDU while its container kept flowing. Typical causes: routing
     path disabled, PDU timeout or E2E failure on the source side, a PDU-collection or
     trigger condition that no longer fires.
   - **STUCK at value**: the PDU keeps arriving but the value no longer follows the
     source. Typical causes: substitute or init value after a timeout or invalid
     detection, update bit not set, stale-data handling in the gateway.
   - **follows hop #n: k of m changes**: the first missed change is the break point.
     A large latency increase before the break points to overload or queueing.
3. `signal_values` on the hops around the break to see the actual values.
4. `events_around` at the break time: SOME/IP-SD NACK, StopOffer or StopSubscribe, DLT
   warnings from the gateway (PduR, Com, SoAd, E2E, SecOC), CAN error frames.

## 3. Common root causes to check

| Symptom | Check |
|---|---|
| ETH side stops, CAN side fine | gateway DLT logs; SOME/IP-SD subscription state (`someip_sd_timeline`); E2E/SecOC failures on the CAN input; NM/partial-network state of the target |
| Both sides stop together | the sender stopped: NM sleep, ECU reset (look for DLT restarts and a gap in all of its messages), bus-off (error frames) |
| Value stuck on ETH | timeout substitute value, update bit, gateway signal-routing vs PDU-routing mismatch |
| Wrong value on ETH | byte order or start bit differ between ARXML and implementation: test alternatives with `extra_hops` |
| Signal never seen on ETH | wrong capture point (tap behind a switch, VLAN filtered), IP fragmentation (see ingest notes), TCP transport (not reassembled yet) |
| Intermittent gaps | `cycle_analysis` on the carrier; check for burst load and error frames at the gap times |

## 4. Record

Record each confirmed or rejected hypothesis with `add_finding`. Cite the hop number,
the ids and the case times.
