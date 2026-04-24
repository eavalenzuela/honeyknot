# REWORK.md — Honeyknot architecture migration plan

## Goal

Turn Honeyknot from a one-shot, client-speaks-first banner faker into a credible multi-protocol malware farm capable of listening on many TCP and UDP ports, speaking enough of each protocol to coax attackers into sending payloads, and capturing those payloads in full.

## Keep

- `config.py` — TOML loader, dataclasses. Extend, don't replace.
- `analyzer.py` — magic-byte identification is protocol-independent.
- `logger.py` — rotating per-port file logger is fine for the structured log stream.
- `cli.py` — argparse wiring; minor changes only.
- Test scaffolding in `tests/`.

## Replace

- `server.py` — process-per-port + threads → single asyncio event loop with many listeners (TCP + UDP).
- `handler.py` — regex table → protocol state machines. Keep regex as *one* strategy for stateless/HTTP-ish handlers.

## Order of work

### Phase 1 — foundation (no user-visible change)

1. Introduce `honeyknot/protocols/` package with a `ProtocolHandler` base: `on_connect(writer)`, `on_data(data, writer, state)`, `on_close(state)`. State is a per-connection dict the handler owns.
2. Rewrite `server.py` around `asyncio`: one `asyncio.start_server` per TCP port, one `loop.create_datagram_endpoint` per UDP port, all in a single process. Keep signal-based graceful shutdown.
3. Add a raw-capture sink: every connection writes `<log_dir>/raw/<ts>_<ip>_<port>.bin` alongside the existing structured log. Unbounded recv with a per-connection byte cap (configurable, default e.g. 10 MB) to bound memory.
4. Port existing HTTP/TCP regex behavior to a `RegexHandler(ProtocolHandler)` so all current TOMLs keep working. Ship behind a feature flag or just cut over once tests pass.

### Phase 2 — protocol depth

5. Add `[service].protocol` key to TOML (`"regex"`, `"ssh"`, `"smtp"`, `"ftp"`, `"telnet"`, `"redis"`, `"http"`). Dispatcher picks the handler class; TOML still supplies banner strings, version strings, rule overrides.
6. Implement server-greets-first handlers: SSH banner exchange (fake KEX_INIT → drop after first client packet is captured), SMTP (220 → HELO/EHLO → MAIL/RCPT/DATA, capture body), FTP (220 → USER/PASS → capture attempted commands), Telnet (IAC negotiation → fake login prompt → capture creds), Redis (multi-command, parse RESP framing).
7. Rewrite the bundled handler TOMLs for those six to use the new protocol types.

### Phase 3 — UDP and binary

8. UDP listeners for DNS, SNMP, SSDP, NetBIOS-NS, Chargen, Memcached. Each is a short protocol-specific parser that emits canned/minimal responses and logs the query.
9. Binary TCP protocols as needed: SMB negotiate, MSSQL pre-login, RDP X.224 — enough handshake to coax an attacker into sending their payload, not full emulation.

### Phase 4 — capture quality

10. Structured JSONL event log (connect, data chunk, close, analyzer hit) separate from raw capture files.
11. Streamed analyzer: run magic-byte detection over the whole captured buffer at close, not just first-recv HTTP bodies. Drop the `POST/PUT`-only gate in `server.py:107`.
12. Optional: write captures as PCAP-ng so existing malware tooling can ingest them.

## Config additions to plan for

- `[service] protocol = "ssh" | "smtp" | ...` (new, required; `"regex"` is the back-compat default)
- `[service] transport = "tcp" | "udp"` (new, default `"tcp"`)
- `[capture] max_bytes = 10485760` (per-connection cap)
- Per-protocol sections, e.g. `[ssh] banner = "SSH-2.0-OpenSSH_7.6p1"`, `[smtp] hostname = "mail.example.com"`.

## Cutover guidance

- Phase 1 is a drop-in: no TOML changes, same behavior, just asyncio underneath. Land it, run for a day, confirm parity.
- Phase 2+ is additive: new `protocol` field defaults to `regex`, so old handlers keep working while new ones roll in one at a time.
- Delete `ProcessPoolExecutor`/`ThreadPoolExecutor` imports only after Phase 1 is verified — don't carry both models simultaneously.

## Rough effort

- Phase 1: ~1 focused day.
- Phase 2: ~2–3 days (one protocol per sitting).
- Phase 3: ~1–2 days depending on how many UDP/binary services you want.
- Phase 4: ~1 day.
