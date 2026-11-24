---
name: someip-sd-analysis
description: Analyse SOME/IP service discovery (offers, finds, eventgroup subscriptions, TTLs, NACKs) to explain why SOME/IP events or methods stop or never start. Use when a SOME/IP consumer does not receive events or a service seems unavailable.
---

# SOME/IP-SD analysis

Events only flow while **all** of these hold:
1. The server offers the service (`OfferService`, ttl > 0) and renews it before the TTL
   expires.
2. The client subscribed to the eventgroup (`SubscribeEventgroup`) and renews before the
   subscription TTL expires.
3. The server acknowledged (`SubscribeEventgroupAck`, ttl > 0), not a
   `SubscribeEventgroupNack` (an Ack with ttl 0).

## Steps

1. `someip_sd_timeline` with `service_id` for the full case. Check:
   - Offer renewal interval against the TTL (a missing renewal makes the service expire).
   - `StopOfferService` (ttl 0) entries.
   - Subscribe -> Ack pairs: each subscribe should get an answer within a few ms.
   - `StopSubscribeEventgroup` or NACK entries, and what happened just before them.
   - Endpoint options: does the subscriber's IP:port match where events are sent?
2. `cycle_analysis` with kind `someip` and `match` for the service: when do the
   notifications stop? Compare with the SD timeline.
3. `events_around` at that time for DLT messages from server and client.

## Typical patterns

- NACK right after a reboot of the client: the server still holds the old subscription
  state; check session ids or the reboot flag.
- Events stop with no SD change: the server application stopped sending (DLT), or the
  events go to a multicast or VLAN that the capture doesn't see.
- Offers continue but no subscribe from the client: the client doesn't see the offers
  (multicast or VLAN configuration), or its own state machine is stuck.
