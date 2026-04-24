# honeyknot

A multi-port, multi-protocol honeypot for farming malware.

Honeyknot listens on many TCP and UDP ports, speaks enough of each protocol
to coax attackers into sending their actual payload, and captures everything
— raw byte streams, structured JSONL events, and deduplicated samples keyed
by SHA-256. Extracted indicators (URLs, IPs, download commands) land in the
event log at capture time, so triage is a `grep` or a `jq` away.

Requires Python 3.11+. Standard library only.

## Usage

```bash
# Minimum: bind IP is required
python -m honeyknot -i 0.0.0.0

# With common options
python -m honeyknot -i 0.0.0.0 -v -hd handlers/ -ld logs/

# From a Python shell
from honeyknot import run_from_interactive_shell
run_from_interactive_shell("0.0.0.0")
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `-i` / `--bind-ip` | *required* | IP to bind listeners to |
| `-hd` / `--handler-dir` | `handlers/` | directory of TOML handler definitions |
| `-ld` / `--log-dir` | `logs/` | directory for all log output |
| `-v` / `--verbose` | off | debug-level console logging |
| `--event-log-max-bytes` | 100 MB | rotate `events.jsonl` at this size |
| `--event-log-backups` | 10 | number of rotated backups to keep |
| `--rate-limit-capacity` | 20 | token bucket capacity per source IP; `<=0` disables |
| `--rate-limit-refill` | 5 | per-IP token refill rate (tokens/sec) |
| `--run-as-user` | *none* | drop to this user after binding (root only) |
| `--run-as-group` | *none* | drop to this group after binding (root only) |
| `--yara-rules` | *none* | path to a `.yar` file or directory of rules (requires `yara-python`) |
| `--pcap` | off | write per-session PCAP-ng files to `logs/pcap/` |
| `--metrics-bind` | *none* | expose Prometheus metrics at `host:port`, e.g. `127.0.0.1:9099` |
| `--raw-dir-max-bytes` | 0 (off) | cap total size of `logs/raw/`; oldest files pruned when exceeded |
| `-tc` / `--thread-count` | 5 | accepted for back-compat; ignored under asyncio |

Signals:
- `SIGINT` / `SIGTERM` — graceful shutdown.
- `SIGHUP` — reload handler TOMLs in place. Unchanged listeners keep running;
  changed ones are stopped and restarted; added/removed ports are
  correspondingly bound/closed. A `config_reload` event records the diff.

Binding to ports <1024 requires root. Use `--run-as-user`/`--run-as-group`
to drop privileges immediately after binding — the daemon will call
`setgroups([])` + `setgid` + `setuid` before `serve_forever` is entered.
If you bind only to non-privileged ports, just run as an unprivileged user
to begin with.

## What you get when it runs

Under `logs/` you get four parallel outputs, each useful at a different level:

```
logs/
  console + per-port .log            # human-readable, rotated, 50 MB × 5
  events.jsonl                       # one JSON object per observed event
  raw/<ts>_<ip>_<port>[_udp].bin     # per-connection / per-datagram byte streams
  samples/<xx>/<sha256>.bin          # content-addressed, deduplicated
```

Every event in `events.jsonl` carries `ts`, `event`, `transport`, `port`,
`protocol`, `peer`, and event-specific fields. Event kinds:

- `connect`, `close` — TCP lifecycle; `close` includes `bytes_in` and `sha256`
- `datagram` — UDP datagram received; includes `bytes` and `sha256`
- `sample_new` — first time we've ever seen this `sha256`
- `analyzer_hit` — magic-byte identifier matched (ELF/PE/PDF/etc.); includes `offset`
- `ioc` — extracted URLs / IPs / download commands / shell snippets
- `protocol` — handler-specific signal: `credentials`, `shell_command`, `http_request`, `vnc_auth_attempt`, etc.

All of these that describe one session share the same `sha256` and `peer`,
so correlating "which IP dropped this binary" is a trivial filter.

## Handler definitions

Each port is configured by one TOML file in the handlers directory. The
minimum is just `[service]` with a port and a protocol name.

### Example: stateful SSH honeypot

```toml
[service]
port = 22
protocol = "ssh"

[ssh]
banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
```

### Example: regex-based HTTP handler (back-compat)

```toml
[service]
port = 8080
type = "http"
protocol = "regex"

[response_headers]
status_line = "HTTP/1.1 200 OK"
headers = ["Server: nginx/1.18.0", "Content-Type: text/html"]

[default_response]
body = "<html><body>ok</body></html>"

[[rules]]
name = "php"
pattern = '^GET /.*\.php'
response = '<?php system($_REQUEST["cmd"]); ?>'
```

### Config reference

`[service]`
- `port` — int, required
- `protocol` — one of the built-in handlers (see below); defaults to `regex`
- `transport` — `tcp` or `udp`; auto-inferred from `protocol` for UDP-only ones
- `type` — `http`, `https`, or `tcp`; defaults to `tcp`. Meaningful only for HTTPS TLS setup
- `description` — free text
- `encoding` — default `utf-8`, used by the regex matcher

`[response_headers]` *(regex handler only)*
- `status_line` — required
- `headers` — list of strings

`[default_response]` *(regex handler only)*
- `body` — sent when no rule matches

`[[rules]]` *(regex handler only, ordered)*
- `name` — label for logs
- `pattern` — Python regex, compiled at load time, case-insensitive
- `response` — string

`[tls]` *(for `type = "https"`)*
- `certfile`, `keyfile` — paths to a PEM cert/key pair

`[<protocol>]` — optional per-handler options, e.g. `[ssh] banner = ...`,
`[smtp] hostname = ...`, `[dns] answer_a = "1.2.3.4"`.

## Built-in protocol handlers

**TCP, stateful session:**
- `ssh` — banner exchange, captures client banner and first KEX packet
- `smtp` — 220 → HELO/EHLO → MAIL/RCPT → DATA → body → QUIT
- `ftp` — full command dialog, credential capture, data channel refused
- `telnet` — IAC negotiation, fake login prompt, fake shell
- `redis` — RESP parser with pipelining, permissive acks
- `vnc` — RFB 3.8 handshake, captures 16-byte auth response then fails
- `http` — full request parser; headers + Content-Length or chunked body, pipelining, `Connection: close`, `h2_preface` event for HTTP/2 scanners
- `mqtt` — CONNECT parser; captures `client_id`/`username`/`password`; CONNACK + PINGRESP + SUBACK
- `mysql` — protocol-10 greeting; parses HandshakeResponse, captures user + auth response bytes; Access denied
- `postgres` — handles SSLRequest + StartupMessage, captures user/db; AuthenticationCleartextPassword; captures password; ErrorResponse

**TCP, binary fingerprinting:**
- `smb` — SMB1 Negotiate response, captures post-negotiate probes
- `mssql` — TDS Pre-Login + captures LOGIN7 + error token
- `rdp` — X.224 Connection Confirm selecting TLS, captures ClientHello + emits `tls_sni` event
- `modbus` — MBAP framing parser, responds to Read Coils / Read Registers / Read Device Identification

**UDP:**
- `dns` — parses query, returns canned A record
- `snmp` — extracts community string, silent (realistic drop on bad community)
- `ssdp` — responds to M-SEARCH with configurable USN/server
- `netbios_ns` — decodes first-level-encoded name, silent
- `chargen` — short fixed reply, refuses amplification
- `memcached` — silent (amplification defense)
- `sip` — OPTIONS 200 / REGISTER 401-nonce to invite Authorization Digest follow-up
- `ipmi` — ASF-RMCP Presence Pong
- `coap` — parses header + Uri-Path; returns 2.05 Content ack

**Fallback:**
- `regex` — back-compat one-shot client-speaks-first matcher; the default

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install ruff pytest

ruff check honeyknot/ tests/
pytest -q
pytest tests/test_protocols_vnc_http.py::TestHTTP::test_chunked_body_decoded
```

## Deployment

See `contrib/` for a `Dockerfile` (python:3.13-slim, non-root,
`CAP_NET_BIND_SERVICE`) and a hardened `honeyknot.service` systemd unit
(`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, restricted
syscall filter). `systemctl reload honeyknot` triggers a SIGHUP reload.

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for remaining planned work.
