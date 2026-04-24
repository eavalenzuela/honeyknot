# ROADMAP.md

Planned work and known gaps, grouped by area and prioritized within each
group. See `REWORK.md` for the historical phase plan that got us here.

## Status as of this file

- 24 protocol handlers: regex + 10 stateful TCP (ssh, smtp, ftp, telnet,
  redis, vnc, http, mqtt, mysql, postgres) + 4 binary TCP (smb, mssql,
  rdp, modbus) + 9 UDP (dns, snmp, ssdp, netbios_ns, chargen, memcached,
  sip, ipmi, coap)
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
- `contrib/Dockerfile` (multi-stage, non-root) and
  `contrib/honeyknot.service` systemd unit with hardening
- GitHub Actions CI (ruff + pytest on 3.11/3.12/3.13)
- 182 tests passing, ruff clean

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
- [ ] **S7 (TCP/102)** + **BACnet (UDP/47808)** — ICS recon; add when
      there is demonstrated traffic on a deployed instance.
- [x] **CoAP (UDP/5683)** — parser + 2.05 Content ack.
- [x] **MQTT (TCP/1883)** — CONNECT parser that captures
      client_id/user/pass; CONNACK + SUBACK + PINGRESP.
- [ ] **MQTT over TLS (TCP/8883)** — add once broader TLS composition
      testing is in place.
- [ ] **WS-Discovery (UDP/3702)** — SOAP-over-UDP amplification target;
      Shodan-visible.
- [x] **MySQL (TCP/3306)** — server-first greeting; login capture;
      Access denied.
- [x] **Postgres (TCP/5432)** — SSLRequest + StartupMessage + cleartext
      password capture.
- [ ] **Telnet over TLS (TCP/992)**, **DNS-over-TLS (TCP/853)**,
      **IMAP (TCP/143/993)**, **POP3 (TCP/110/995)** — regularly probed;
      not yet implemented.
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
- [x] **Dockerfile** at `contrib/Dockerfile` (python:3.13-slim, non-root).
      `docker-compose.yml` still TODO.
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
- [ ] **No handler-isolation lint.** A handler that writes to `self.foo`
      instead of `ctx.state["foo"]` would silently leak between sessions.
      Add a lightweight ast-based lint pass in CI.
- [ ] **No asyncio-level integration tests.** Every handler test uses a
      fake `StreamWriter`. Add a few that go through a real
      `asyncio.start_server` + `asyncio.open_connection` to catch
      wire-format regressions (we caught two of those only via live
      smoke scripts).
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
- [ ] Publish to PyPI as `honeyknot`, so users can `pipx install honeyknot`
      instead of running from a clone.
