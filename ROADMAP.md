# ROADMAP.md

Planned work and known gaps, grouped by area and prioritized within each
group. See `REWORK.md` for the historical phase plan that got us here.

## Status as of this file

- 33 protocol handlers: regex + 14 stateful TCP (ssh, smtp, ftp, telnet,
  redis, vnc, http, mqtt, mysql, postgres, imap, pop3, ldap, adb) + 5 binary
  TCP (smb, mssql, rdp, modbus, s7) + 13 UDP (dns, snmp, ssdp, netbios_ns,
  chargen, memcached, sip, ipmi, coap, wsd, bacnet, tftp, ntp)
- Generic TLS wrapping (`[tls] enabled = true` on any TCP handler);
  bundled IMAPS/POP3S/MQTTS/SMTPS TOMLs; `python -m honeyknot.gencert`
  self-signed cert helper
- MQTT PUBLISH now captures topic + payload bytes for IOC pipeline
- `EVENTS.md` catalog enumerating every emitted event with fields
- PyPI-ready packaging (setuptools build-system, classifiers,
  `honeyknot-gencert` entry point)
- Single asyncio event loop, one process
- Raw per-session captures, content-addressed sample store (SHA-256) with
  `.meta.json` sidecars, JSONL event log with size-based rotation, IOC
  extraction at capture time with gzip/zlib/base64 one-layer peel
- Per-source rate limiting (token bucket per IP)
- Privilege drop via `--run-as-user` / `--run-as-group`
- Handler supervision with auto-restart on crash + `port_down` / `port_up` events
- Write buffer bounds on every TCP connection (OOM protection)
- HTTPS composition verified (type=https + protocol=http)
- Optional YARA scanning via `--yara-rules`
- Per-session PCAP-ng capture via `--pcap` with synthesized IPv4+TCP framing
- Prometheus `/metrics` endpoint via `--metrics-bind`
- SIGHUP reload of handler TOMLs with diff reconciliation
- Raw-dir retention sweeper via `--raw-dir-max-bytes`
- TLS SNI extraction from RDP post-confirm captures → `tls_sni` event
- HTTP/2 preface detection → `h2_preface` event (+ 505 reply)
- `contrib/Dockerfile`, `contrib/docker-compose.yml`, and
  `contrib/honeyknot.service` systemd unit with hardening
- Handler-isolation lint: static check that protocol handlers don't
  mutate `self` outside `__init__` (would leak state across sessions)
- Real-asyncio integration tests against live `asyncio.start_server` /
  `create_datagram_endpoint` for connection lifecycle, rate limiting,
  sample dedup, connection idle-timeout, and UDP datagram path
- GitHub Actions CI (ruff + pytest on 3.11/3.12/3.13)
- Expanded analyzer signatures (Mach-O/Java-class/7z/xz/bz2/cab/dex/lnk/
  wasm/shebang) and IOC extraction (IPv6, `.onion`, Windows LOLBINs)
- Per-connection idle timeout (`--conn-idle-timeout`), IPv4-only-safe pcap,
  config port-range + duplicate-port validation, DRY'd capture-finalize path
- `honeyknot-stats` offline events.jsonl analyzer; `--version` /
  `--list-protocols` CLI flags; build-info/uptime/bytes-captured metrics
- 299 tests passing, ruff clean

## Capture quality & analysis

- [x] **YARA integration.** Optional via `--yara-rules`; no-op if
      `yara-python` isn't installed. Matches land in `yara_match` events
      and aggregate into sample sidecars.
- [x] **Per-source rate limiting.** Token-bucket limiter in
      `honeyknot/ratelimit.py`; configurable via `--rate-limit-capacity` and
      `--rate-limit-refill`. Emits `rate_limited` event on drop.
- [x] **Transparent decompression in the IOC extractor.** One layer of
      gzip / zlib / base64 is peeled off before regex extraction.
- [x] **PCAP-ng export.** `--pcap` enables per-session `.pcapng` files in
      `logs/pcap/` with synthesized Ethernet+IPv4+TCP framing so Wireshark
      "Follow TCP Stream" works out of the box.
- [x] **Raw-dir retention / sweeper.** `--raw-dir-max-bytes` enables a
      background task that prunes oldest files by mtime when the cap is
      exceeded. Emits `retention_sweep` events.
- [x] **Sample metadata sidecar.** `logs/samples/<xx>/<sha>.meta.json` now
      tracks `first_seen`, `last_seen`, `hit_count`, `size`, distinct
      `peers` (capped at 50), and aggregated `iocs`.

## Missing high-value protocols

- [x] **SIP (UDP/5060)** — OPTIONS/REGISTER/INVITE parser; 401-nonce
      challenge invites digest credential submission.
- [x] **IPMI (UDP/623)** — ASF-RMCP Presence Pong responder.
- [x] **Modbus (TCP/502)** — MBAP framing + Read Coils / Read Registers
      / Read Device ID.
- [x] **S7 (TCP/102)** — COTP Connection Confirm + S7 Setup
      Communication ack; logs subsequent Job frames.
- [x] **BACnet/IP (UDP/47808)** — Who-Is → I-Am responder with
      configurable device instance and vendor id.
- [x] **CoAP (UDP/5683)** — parser + 2.05 Content ack.
- [x] **MQTT (TCP/1883)** — CONNECT parser that captures
      client_id/user/pass; CONNACK + SUBACK + PINGRESP.
- [x] **MQTT over TLS (TCP/8883)** — generic `[tls]` wrapping enables
      this; bundled `mqtts_8883.toml` ready.
- [x] **WS-Discovery (UDP/3702)** — Probe logger + non-amplifying
      ProbeMatches reply (guaranteed smaller than request).
- [x] **MySQL (TCP/3306)** — server-first greeting; login capture;
      Access denied.
- [x] **Postgres (TCP/5432)** — SSLRequest + StartupMessage + cleartext
      password capture.
- [x] **IMAP (TCP/143)** — LOGIN + AUTHENTICATE PLAIN credential capture.
- [x] **POP3 (TCP/110)** — APOP banner + USER/PASS / APOP digest capture.
- [x] **IMAP-TLS (TCP/993)** and **POP3-TLS (TCP/995)** — bundled
      `imaps_993.toml` and `pop3s_995.toml` use generic TLS wrapping.
- [x] **SMTPS (TCP/465)** — bundled `smtps_465.toml`.
- [x] **TFTP (UDP/69)** — RRQ/WRQ filename + mode capture; ERROR reply
      (non-amplifying). Bundled `tftp_69.toml`.
- [x] **NTP (UDP/123)** — mode-3 client → same-size mode-4 reply;
      mode-6/mode-7 (`monlist`) logged + dropped. Bundled `ntp_123.toml`.
- [x] **ADB (TCP/5555)** — Android Debug Bridge; `A_CNXN` handshake +
      `A_OPEN` `shell:` command capture. Bundled `adb_5555.toml`.
- [x] **LDAP (TCP/389)** — BER `bindRequest` DN+password capture and
      `searchRequest` baseObject. Bundled `ldap_389.toml`.
- [ ] **Telnet-TLS (TCP/992)** and **DNS-over-TLS (TCP/853)** — add
      TOMLs when there is demonstrated traffic on a deployed instance.
- [x] **HTTPS coverage for the new HTTP handler.** Verified live with a
      self-signed cert: TLS terminates, Content-Length body is consumed
      in full, rules match.

## Operational readiness

- [x] **Privilege drop.** `--run-as-user` / `--run-as-group` flags: bind
      as root, drop to unprivileged user via setgroups/setgid/setuid
      *after* all listeners are bound, *before* accepting connections.
- [x] **Prometheus metrics endpoint.** `--metrics-bind host:port` starts
      a stdlib asyncio HTTP server serving `/metrics`. Counts events
      broken down by `(event, port, protocol, transport)`, plus a
      `honeyknot_unique_samples` gauge from the sample store.
- [x] **`systemd` unit file** at `contrib/honeyknot.service` with
      `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `AmbientCapabilities`,
      `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, restricted
      syscall filter.
- [x] **Dockerfile** + **docker-compose.yml** at `contrib/`
      (python:3.13-slim, non-root, CAP_NET_BIND_SERVICE,
      read-only root, tmpfs /tmp, bounded logs volume).
- [x] **Handler supervision with auto-restart.** Supervisor task per port
      backs off (1s → 32s capped) and re-binds on crash. Emits
      `port_down` on failure and `port_up` on successful rebind.
- [x] **Back-pressure on slow clients.** Every TCP connection gets
      `set_write_buffer_limits(high=64 KiB, low=16 KiB)` on accept.
- [x] **SIGHUP reload.** Diffs handler TOMLs on SIGHUP; unchanged
      listeners keep running, changed ones restart, added/removed ports
      are reconciled. `config_reload` event records the diff.

## Protocol / code correctness gaps

- [x] **Binary frames logged as text.** False alarm on audit: SMB already
      logs compactly (`"%d bytes (head=<hex>)"`), and RDP/MSSQL don't use
      the per-port request logger at all — they emit semantic messages
      to their module loggers.
- [x] **Handler-isolation lint.** `tests/test_handler_isolation.py`
      parametrizes over every handler module and fails if any
      `on_connect`/`on_data`/`on_close`/`on_datagram` body contains
      `self.<attr> = ...`. All 27 handler modules currently pass.
- [x] **asyncio-level integration tests.** `tests/test_server_integration.py`
      starts real listeners via `PortServer` / `UdpPortServer` on
      ephemeral ports and verifies connection lifecycle, rate limiting,
      sample dedup, and UDP datagram path end-to-end.
- [x] **HTTP handler: HTTP/2 rejection.** Explicit `h2_preface` event
      emitted and 505 returned when the preface is observed.
- [x] **RDP: post-confirm TLS ClientHello SNI parsing.** `tls_sni` event
      with the hostname from the server_name extension.

## Small polish / debt

- [ ] `handlers/` lacks TOMLs for some of the protocols we implemented
      on purpose (chargen, memcached, netbios_ns, ssdp, snmp are all
      shipped — but worth double-checking the bundled set matches what
      users are likely to enable by default).
- [x] `logs/` is now in `.gitignore`.
- [ ] The regex handler still decodes the full incoming chunk as UTF-8
      before matching; for partly binary protocols this wastes CPU.
      Consider matching against bytes regex directly.
- [x] CI: `.github/workflows/ci.yml` runs ruff + pytest on push and PR
      across Python 3.11 / 3.12 / 3.13.
- [~] PyPI packaging wired up in `pyproject.toml` (setuptools
      build-system, classifiers, `honeyknot` + `honeyknot-gencert`
      entry points). Wheel builds locally. Actual upload to PyPI is
      a release chore and not yet done.
