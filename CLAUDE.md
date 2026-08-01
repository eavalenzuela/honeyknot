# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Honeyknot is a multi-port, multi-protocol honeypot written in Python (3.11+, stdlib only) for farming malware. It listens on many TCP and UDP ports, speaks enough of each protocol to coax attackers past initial negotiation, and captures everything: raw per-session byte streams, JSONL event log, and content-addressed (SHA-256) sample store. IOCs (URLs, IPs, download commands) are extracted at capture time; magic-byte analysis runs on the full captured buffer; captured bytes are also matched against a CVE/technique signature table. Honeyknot serves nothing real, so a signature hit is always an *attempt* — never describe it as detecting an exploited vulnerability.

Two handlers go further than negotiate-and-log, because their traffic is worthless until the attacker commits: telnet runs an emulated BusyBox shell (`shell.py`) so IoT loaders pass their own fingerprinting checks, and HTTP serves vulnerable-looking responses with canary credentials (`deception.py`) so the second stage arrives. Both reconstruct dropped files as artifacts. Optionally (`--fetch-payloads`, off by default) honeyknot will download URLs it sees in captures.

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

Key flags: `-v` debug logging, `-tc` is accepted for back-compat but is a no-op under the asyncio concurrency model. `--fetch-payloads` (plus `--fetch-max-bytes` / `--fetch-timeout` / `--fetch-allow-private`) turns on outbound payload retrieval — off by default and it should stay that way unless the operator asks for it.

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
- `exploits.py` — `classify()` returns exploit-signature hits over captured bytes (head 256 KB + percent-decoded/compressed variants); `summarize()` flattens them for an event line. Signature ids are CVE ids where unambiguous, kebab-case technique slugs otherwise (slugs never start with `CVE-`). `severity` = impact had it landed on a real service, not match confidence
- `shell.py` — emulated BusyBox/Linux shell: virtual filesystem, per-arch ELF header, table-driven command dispatch. `ShellSession.execute(line)` returns a `ShellResult` of output + `(name, fields)` events + `(filename, bytes)` artifacts. Backs the telnet handler and the HTTP deception layer's command execution. Executes nothing
- `deception.py` — `DeceptionSite.respond()` returns a vulnerable-looking `WebResponse`, or None to fall through to operator config (config always wins). All secrets are deterministic canary tokens seeded from `[http] canary_seed`
- `fetcher.py` — `PayloadFetcher`, OPT-IN outbound retrieval of URLs seen in captures. Read the module docstring before touching it: it documents attribution, SSRF and live-malware-on-disk risks plus the mitigations
- `samples.py` — `SampleStore` content-addressed writes to `logs/samples/<xx>/<sha>.bin` with filesystem-based dedup; `<sha>.meta.json` sidecar aggregates `iocs`, `analyzer`, `yara`, `exploits`, `peers`, `first_seen`/`last_seen`/`hit_count`
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

`ctx.artifact(name, data, kind="upload")` hands a *reconstructed* file — an echo-loader binary, a heredoc body, an upload payload — to the sample store and returns its sha256. Use it whenever a handler can extract a file from the protocol framing: the extracted bytes hash to the same digest as the identical sample dropped over a different transport, so the store deduplicates across handlers. Artifacts run the full analyze/IOC/YARA/exploit pipeline and emit a top-level `artifact` event.

**Reserved kwargs gotcha:** `name`, `transport`, `port`, `protocol` and `peer` belong to the sink, which supplies them itself. Passing any of them to `ctx.event()` is a duplicate-keyword **TypeError at emit time** — not at import, not in tests that don't hit that branch. Pick another key: existing handlers use `command_name`, `method`, `protocol_name`, `type_name` for exactly this reason.

### Request flow (TCP)

1. `cli.py:main()` → `HoneyknotDaemon.start()` → `asyncio.run(_run())`
2. `_run` loads `handlers/*.toml`, constructs `EventSink` + `SampleStore`, builds one `PortServer` or `UdpPortServer` per config
3. `PortServer.start` binds the socket (+ TLS context for `type = "https"`); `serve` runs `serve_forever`
4. Per connection: `_handle_connection` opens a raw-capture file in `logs/raw/`, builds `ConnectionContext`, emits `connect`, loops `reader.read(65536)` → write to capture + append to in-memory `captured` buffer (capped at `max_capture_bytes`, default 10 MB) → `handler.on_data`, until EOF / `ctx.closed` / cap reached
5. At close: `_finalize_capture` → `_finalize_payload`, then emits `close` with the `sha256`

### `_finalize_payload` (server.py)

The one place a payload gets analyzed, shared by four callers so none can drift: TCP capture-close, UDP datagram, `ctx.artifact()`, and a fetched payload. Given bytes it hashes them, stores them in `SampleStore`, runs `scan_payload` → `analyzer_hit`, `extract_iocs` → `ioc`, `exploits.classify` → `exploit_attempt`, YARA → `yara_match`, emits `sample_new` on first sight, schedules `fetcher.schedule(urls)` if fetching is on, and merges everything into the `.meta.json` sidecar. Returns the digest. Payloads under 4 bytes are skipped and return None.

### Request flow (UDP)

1. `_UdpProtocol.datagram_received` dumps the datagram to `logs/raw/<ts>_<ip>_<port>_udp.bin`
2. `_finalize_datagram` → `_finalize_payload`
3. Emits `datagram` event with `sha256`
4. Schedules `handler.on_datagram(data, ctx)` as a task

### Event shapes

Handler events do **not** appear as their own `event` kind. `server.py:_emit_protocol` wraps them: `event: "protocol"` with the handler's signal in a `name` field. Top-level kinds are the ones the server/pipeline emits directly (`connect`, `close`, `datagram`, `rate_limited`, `analyzer_hit`, `ioc`, `exploit_attempt`, `yara_match`, `sample_new`, `artifact`, `payload_fetch`, plus daemon-level ones). `EVENTS.md` is the operator-facing catalog — update it in the same change as any new or renamed event field.

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

The `[<protocol>]` table lands on `ServiceConfig.protocol_opts` verbatim; handlers read it with `.get()` and their own defaults. Two worth knowing:

- `[http]` — `deception` (bool, default true), `profile` (`generic`/`docker`/`elasticsearch`/`tomcat`/`springboot`/`router`), `hostname`, `canary_seed`, `server`, `docker_version`, `elasticsearch_version`, plus shell options `shell_user`, `arch`, `kernel`
- `[telnet]` — `hostname`, `arch`, `kernel`, `motd`, `reject_first`

HTTP response selection is now **deception routes → `[[rules]]` → `[default_response]`**. That changed behavior for existing deployments; `[http] deception = false` restores the old order. `handler.match_rule()` returns None when nothing matched, which is what lets a caller distinguish "a rule matched" from "fall through".

Regex-handler-specific sections (`[response_headers]`, `[default_response]`, `[[rules]]`) are documented in `README.md`. Patterns are compiled at load time; invalid regex raises `ValueError` before the daemon starts.

### Back-compat notes

- Old TOMLs without `protocol` default to `regex` — they keep working.
- `type` is optional now, defaulting to `tcp`.
- `-tc` / `--thread-count` CLI flag is accepted and ignored.

### Roadmap

`ROADMAP.md` is the canonical list of planned work and known gaps. Prefer updating the roadmap to leaving TODO comments in code.
