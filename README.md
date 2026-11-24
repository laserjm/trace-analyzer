# trace-analyzer

Agent tooling for analysing automotive E/E traces. A Python **MCP server** (`trace-tools`)
parses BLF/ASC, MF4, PCAP/PCAPNG (SOME/IP, SOME/IP-SD, SoAd PDUs, DoIP, SocketCAN) and DLT
into a per-case DuckDB database. It resolves signal routes from ARXML and gives an agent
(GitHub Copilot CLI, Claude Code, ...) tools that return compact answers instead of raw
dumps. The agent's domain knowledge lives in `.github/copilot-instructions.md` and
`.github/skills/`.

```
cases/<case-id>/raw/*.blf|asc|mf4|pcap(ng)|dlt ──ingest──► db/trace.duckdb ─┐
cases/<case-id>/arxml/*.arxml ───────────────────────► signal routes ────────┼─► MCP tools ─► agent
cases/<case-id>/screenshots/*.png ───────────────────────────────────────────┘
```

## Quick start

```bash
uv sync
uv run python scripts/make_demo_case.py      # synthetic case: CAN signal lost on the ETH side at t=30 s
uv run pytest -q
```

### GitHub Copilot CLI

`.github/mcp.json` registers the server. Start `copilot` **from the repository root**,
confirm folder trust, choose Claude Opus 5.5 with `/model`, then for example:

> Case demo: the HPC does not receive DoorLockState. Find where and why it gets lost.

Check with `/mcp` that `trace-tools` is connected and with `/skills list` that the three
skills are loaded.

### Other MCP clients (optional)

The server works with any MCP client. Example for Claude Code:

```bash
claude mcp add trace-tools -e TRACE_CASES_DIR=cases -- uv run trace-mcp
```

Claude Code reads `.claude/skills/`; copy or symlink `.github/skills/*` there.

## A case

```
cases/<case-id>/
  raw/          trace files, any depth (.blf .asc .mf4 .pcap .pcapng .dlt)
  arxml/        system description(s)
  screenshots/  .png/.jpg
  case.json     optional: ticket text, channel_map {"CAN1": "<ARXML cluster or channel>"}
  findings.md   written by the agent (add_finding)
  db/           generated
```

Case data is git-ignored on purpose: traces can contain VINs, positions and confidential
content.

## Tools

| Tool | Purpose |
|---|---|
| `list_cases`, `ingest_case`, `case_overview` | orientation; ingest is incremental |
| `set_time_offset`, `set_channel_name` | clock alignment between files; map log channels to ARXML buses |
| `find_signal`, `signal_routes` | ARXML lookup: every hop of a signal (CAN frame, socket header id, container PDU, gateway, sender -> receiver) |
| `trace_signal` | follows a signal over all hops: presence, period, gaps, STOPPED/STUCK, change-following with latency, first missed change |
| `signal_values` | decoded raw values of one hop (changes or samples, downsampled) |
| `cycle_analysis` | cycle time, gaps, stopped / started-late messages (CAN, SOME/IP, PDU-over-IP) |
| `events_around` | merged timeline: CAN error frames, SD, SOME/IP errors, DLT warn+, DoIP |
| `someip_sd_timeline`, `dlt_search` | protocol-specific views |
| `sql` | read-only DuckDB SELECT (single statement, no file access), bounded output |
| `view_screenshot` | returns an image to the model |
| `add_finding` | appends to the case notebook `findings.md` |

All times in and out are **case time** (seconds since the earliest timestamp of the case).

## Extending

- **Domain knowledge**: add a skill per topic (E2E profiles of your platform, startup or
  NM sequences, known fault signatures) under `.github/skills/<name>/SKILL.md`. Skills
  change more often than the tools.
- **Vendor ARXML tooling**: `SystemModel.routes()` in `src/trace_mcp/arxml.py` returns
  plain hop dicts. If your vendor library resolves routes more completely, wrap it so it
  returns the same dicts. Until then, the agent can pass hops it gets from elsewhere via
  `trace_signal(extra_hops=...)`.
- **New detectors**: add a function to `analysis.py` and a `@mcp.tool()` wrapper in
  `server.py`. Keep outputs bounded.

## Status and known gaps

Tested with synthetic data only (`scripts/make_demo_case.py`, `tests/`). Before relying on
it, verify against real files:

- **MF4** bus logging (`CAN_DataFrame`): written to the ASAM standard but untested with
  real logger files. Ethernet groups and decoded measurement channels in MF4 are not
  ingested yet.
- **ARXML**: covers AUTOSAR 4.x I-SIGNAL -> I-PDU -> CAN frame / socket connection (header
  id) / container PDU, SYSTEM-SIGNAL grouping, gateway signal and PDU mappings, and ECU
  ports. Not covered yet: signal groups and SOME/IP transformer serialisation, SOME/IP
  service-interface deployments, FlexRay, LIN, SecOC/E2E header offsets, compu methods
  (values are raw).
- **Container PDUs**: big-endian headers assumed.
- **Ethernet**: no IP reassembly and no TCP stream reassembly (SOME/IP over TCP is parsed
  per segment). TECMP/CMP logger encapsulation and DLT over UDP are not decoded yet.
- **Performance**: decoding is plain Python. Fine for traces up to a few GB; vectorise
  `tracing.hop_series` and the pcap ingest when you hit the limits.
