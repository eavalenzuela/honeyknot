# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Honeyknot is a multi-port, multi-protocol honeypot written in Python (3.11+, stdlib only) for farming malware. It listens on many TCP and UDP ports, speaks enough of each protocol to coax attackers past initial negotiation, and captures everything: raw per-session byte streams, JSONL event log, and content-addressed (SHA-256) sample store. IOCs (URLs, IPs, download commands) are extracted at capture time; magic-byte analysis runs on the full captured buffer.

## Running

```bash
# CLI (bind IP required)
python3 -m honeyknot -i <bind_ip>

# Common options
python3 -m honeyknot -i 0.0.0.0 -v -hd handlers/ -ld logs/ \
    --event-log-max-bytes 104857600 --event-log-backups 10

# From Python interactive shell
from honeyknot import run_from_interactive_shell
run_from_interactive_shell("0.0.0.0")
```

Key flags: `-v` debug logging, `-tc` is accepted for back-compat but is a no-op under the asyncio concurrency model.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install ruff pytest

# Lint
ruff check honeyknot/ tests/

# Run all tests
pytest

# Single file / test
pytest tests/test_handler.py
pytest tests/test_config.py::TestLoadHandler::test_invalid_regex_caught_at_load
```

## Architecture

### Module layout (`honeyknot/` package)

- `cli.py` — argparse, entry point wiring
- `config.py` — TOML loading, validation, `ServiceConfig` dataclass; owns `VALID_PROTOCOLS` / `VALID_TRANSPORTS` / `UDP_PROTOCOLS`
- `server.py` — `PortServer` (TCP), `UdpPortServer` (UDP), and `HoneyknotDaemon` (top-level asyncio event loop + signal handling)
- `handler.py` — regex request matching and response building for the `regex` back-compat handler
- `analyzer.py` — magic-byte identification (`analyze_payload` for prefix match, `scan_payload` for full-buffer scan that returns `offset`)
- `ioc.py` — regex-based IOC extraction (URLs, IPv4, download commands, shell snippets) gated by printable ratio
- `samples.py` — `SampleStore` content-addressed writes to `logs/samples/<xx>/<sha>.bin` with filesystem-based dedup
- `events.py` — `EventSink` JSONL writer with size-based rotation
- `logger.py` — stdlib `logging` setup with per-port `RotatingFileHandler`
- `protocols/` — one module per protocol handler; `__init__.py` owns the registry

### Concurrency model

**Single asyncio event loop, one process.** One `asyncio.start_server` per TCP port, one `loop.create_datagram_endpoint` per UDP port. Graceful shutdown via `loop.add_signal_handler` on SIGINT/SIGTERM. There is no process pool and no thread pool.

### ProtocolHandler contract

Handlers subclass `honeyknot.protocols.base.ProtocolHandler` and implement any subset of:

- `async on_connect(ctx: ConnectionContext)` — TCP: runs immediately after accept. Server-greets-first protocols send their banner here.
- `async on_data(data: bytes, ctx: ConnectionContext)` — TCP: runs per chunk read.
- `async on_close(ctx: ConnectionContext)` — TCP: runs at teardown.
- `async on_datagram(data: bytes, ctx: DatagramContext)` — UDP.

A single handler instance is constructed per port at startup. **All per-session state must live on `ctx.state`**, not on the handler instance, because the instance is shared across connections. Handlers request connection shutdown via `ctx.close()` (TCP) and emit structured protocol events via `ctx.event(name, **fields)`.

### Request flow (TCP)

1. `cli.py:main()` → `HoneyknotDaemon.start()` → `asyncio.run(_run())`
2. `_run` loads `handlers/*.toml`, constructs `EventSink` + `SampleStore`, builds one `PortServer` or `UdpPortServer` per config
3. `PortServer.start` binds the socket (+ TLS context for `type = "https"`); `serve` runs `serve_forever`
4. Per connection: `_handle_connection` opens a raw-capture file in `logs/raw/`, builds `ConnectionContext`, emits `connect`, loops `reader.read(65536)` → write to capture + append to in-memory `captured` buffer (capped at `max_capture_bytes`, default 10 MB) → `handler.on_data`, until EOF / `ctx.closed` / cap reached
5. At close: `_finalize_capture` hashes the buffer, stores it in `SampleStore`, runs `scan_payload` and `extract_iocs`, emits `analyzer_hit` / `ioc` / `sample_new` as appropriate, then emits `close` with the `sha256`

### Request flow (UDP)

1. `_UdpProtocol.datagram_received` dumps the datagram to `logs/raw/<ts>_<ip>_<port>_udp.bin`
2. `_finalize_datagram` hashes, stores, analyzes, extracts IOCs, emits correlated events
3. Emits `datagram` event with `sha256`
4. Schedules `handler.on_datagram(data, ctx)` as a task

### Handler definitions (`handlers/*.toml`)

```toml
[service]
port = 22
protocol = "ssh"      # see VALID_PROTOCOLS in config.py
transport = "tcp"     # auto-inferred from protocol; usually omitted
type = "tcp"          # only meaningful for HTTPS TLS setup
description = "..."
encoding = "utf-8"    # for the regex handler's decode step

[ssh]                 # optional per-protocol section, keys depend on handler
banner = "SSH-2.0-OpenSSH_8.9"
```

Regex-handler-specific sections (`[response_headers]`, `[default_response]`, `[[rules]]`) are documented in `README.md`. Patterns are compiled at load time; invalid regex raises `ValueError` before the daemon starts.

### Back-compat notes

- Old TOMLs without `protocol` default to `regex` — they keep working.
- `type` is optional now, defaulting to `tcp`.
- `-tc` / `--thread-count` CLI flag is accepted and ignored.

### Roadmap

`ROADMAP.md` is the canonical list of planned work and known gaps. Prefer updating the roadmap to leaving TODO comments in code.
