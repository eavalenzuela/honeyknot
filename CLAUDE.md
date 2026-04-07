# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Honeyknot is a multi-port honeypot written in Python (3.11+, stdlib only) for farming malware. It listens on configurable ports, responds to incoming connections with crafted responses (HTTP, HTTPS, or raw TCP), logs all incoming request data, and analyzes captured payloads for known file types.

## Running

```bash
# CLI with required bind IP
python3 -m honeyknot -i <bind_ip>

# With options
python3 -m honeyknot -i 0.0.0.0 -v -tc 10 -hd handlers/ -ld logs/

# From Python interactive shell
from honeyknot import run_from_interactive_shell
run_from_interactive_shell("0.0.0.0")
```

Key CLI flags: `-v` verbose/debug logging, `-tc` thread count per port (default 5).

## Development

```bash
# Create venv and install tools
python3 -m venv .venv && source .venv/bin/activate
pip install ruff pytest

# Lint
ruff check honeyknot/ tests/

# Run all tests
pytest

# Run a single test file or test
pytest tests/test_handler.py
pytest tests/test_config.py::TestLoadHandler::test_invalid_regex_caught_at_load
```

## Architecture

### Module layout (`honeyknot/` package)

- `cli.py` — argparse, entry point wiring
- `config.py` — TOML handler loading, validation, dataclasses (`ServiceConfig`, `Rule`, `ResponseHeaders`)
- `server.py` — `PortServer` (per-port socket + thread pool) and `HoneyknotDaemon` (process pool + signal handling)
- `handler.py` — pure request matching and response building (no I/O)
- `analyzer.py` — file type identification by magic bytes, integrated into connection handling
- `logger.py` — stdlib `logging` setup with per-port `RotatingFileHandler`

### Concurrency model

One `ProcessPoolExecutor` process per port, each running a `PortServer` with a `ThreadPoolExecutor` (sized by `-tc`). The accept loop uses `socket.settimeout(1.0)` and checks a `multiprocessing.Event` for graceful shutdown on SIGINT/SIGTERM.

### Request flow

1. `cli.py:main()` → `HoneyknotDaemon.start()` → loads all `handlers/*.toml` via `config.load_all_handlers()`
2. Spawns one process per config → `PortServer.run()` binds socket, enters accept loop
3. Each connection submitted to thread pool → `_handle_connection()`: recv → log → `handler.match_request()` → sendall → `analyzer.analyze_payload()` on POST/PUT bodies → close

### Handler definitions (`handlers/*.toml`)

Single TOML format for all protocols. Key sections:
- `[service]` — `port` (int), `type` ("http"/"https"/"tcp"), optional `encoding`
- `[response_headers]` — `status_line` + `headers` array (HTTP/HTTPS only)
- `[default_response]` — fallback `body` when no rule matches
- `[[rules]]` — ordered regex `pattern` + `response` pairs (first match wins, case-insensitive)

Regex patterns are compiled and validated at config load time.
