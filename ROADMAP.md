# ROADMAP.md

Planned work and known gaps, grouped by area and prioritized within each
group. See `REWORK.md` for the historical phase plan that got us here.

## Status as of this file

- 42 registered protocol handlers: regex + 20 stateful TCP (ssh, smtp, ftp,
  telnet, redis, vnc, http, mqtt, mysql, postgres, imap, pop3, ldap, adb,
  rtsp, socks, rsync, finger, amqp, zookeeper) + 7 binary TCP (smb, mssql,
  rdp, modbus, s7, jdwp, rmi) + 14 UDP (dns, snmp, ssdp, netbios_ns,
  chargen, memcached, sip, ipmi, coap, wsd, bacnet, tftp, ntp, rpcbind)
- Exploit-attempt classification (`honeyknot/exploits.py`): 83 signatures
  over 80 ids (40 of them CVEs, the rest technique slugs) run against every
  captured payload, emitted as `exploit_attempt` and aggregated into the
  sample sidecar. Every hit is an attempt — honeyknot serves nothing real
- Emulated BusyBox shell (`honeyknot/shell.py`) behind telnet and the HTTP
  deception layer: virtual filesystem, per-architecture ELF header,
  echo-loader and heredoc reconstruction into `artifact` events
- HTTP deception layer (`honeyknot/deception.py`): vulnerable-looking routes
  (.env / .git / wp-config / actuator / Docker API / Elasticsearch / login
  forms / webshell `?cmd=`) with deterministic canary tokens
- Opt-in payload fetching (`honeyknot/fetcher.py`, `--fetch-payloads`) with
  SSRF vetting before and after connect, size/time/concurrency/total caps
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
- `ctx.artifact()` on both contexts: handler-reconstructed files go through
  the same analyze/IOC/YARA/exploit pipeline as a session capture, so the
  sample store deduplicates the same payload across transports
- HTTP `CONNECT` accepted as proxy abuse; tunneled bytes captured, nothing
  relayed anywhere
- 710 tests passing as of this commit, ruff clean

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
      `peers` (capped at 50), aggregated `iocs`, and — since this batch —
      an `exploits` array keyed on `(id, title)`, so a sample delivered
      through two different vehicles lists both.

## Deception, emulation, and payload acquisition

- [x] **Exploit-attempt classification.** `honeyknot/exploits.py` matches
      captured bytes against CVE-anchored and technique signatures and emits
      `exploit_attempt`; hits are merged into `<sha>.meta.json` under
      `exploits`. Scanning is bounded (256 KB head) and each signature
      reports once per payload.
- [x] **Emulated shell behind telnet.** Post-login is a table-driven
      BusyBox emulator rather than a bare `#`, so a Mirai-class loader gets
      through its `busybox <TOKEN>` / `/proc/mounts` / `cat /bin/echo`
      fingerprinting and reaches delivery. New `[telnet]` options: `arch`,
      `motd`, `reject_first`, `kernel`.
- [x] **Reconstructed artifacts.** `ctx.artifact()` on both contexts;
      echo-loader binaries, heredoc drops and `| sh` bodies are rebuilt and
      stored with their own digest, emitting an `artifact` event.
- [x] **HTTP deception routes + canary tokens.** Response order is now
      deception → `[[rules]]` → `[default_response]`; disable with
      `[http] deception = false`. Canary credentials are deterministic per
      deployment so a leak is attributable.
- [x] **Opt-in payload fetching.** `--fetch-payloads` downloads URLs seen
      in captures into the sample store. Off by default; the three risks
      (attribution, SSRF, live malware on disk) are documented in
      `fetcher.py` and `README.md` rather than buried.

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
- [x] **RTSP (TCP/554)** — IP-camera mimic; 401 offering Digest+Basic to
      harvest vendor-default camera credentials, then SDP so the scanner
      walks on to SETUP/PLAY. Bundled `rtsp_554.toml`.
- [x] **SOCKS4/4a/5 (TCP/1080)** — open proxy that relays nothing;
      records the destination asked for and absorbs the tunnel payload.
      Bundled `socks5_1080.toml`.
- [x] **JDWP (TCP/8000)** — echoes the handshake and answers the
      VirtualMachine command set so shellifier-style tools reach
      `invokeMethod`; scrapes the command line out. Bundled `jdwp_8000.toml`.
- [x] **RMI registry (TCP/1099)** — completes the JRMP handshake so
      ysoserial/JNDI payloads arrive in full, then mines the serialized
      stream for class names and gadget markers. Never deserializes.
      Bundled `rmi_1099.toml`.
- [x] **ZooKeeper (TCP/2181)** — four-letter-word admin commands plus the
      binary ConnectRequest/ping path. Bundled `zookeeper_2181.toml`.
- [x] **rsync (TCP/873)** — module list bait, challenge-auth capture, and
      the argument vector (`--sender` distinguishes exfiltration from a
      push). Bundled `rsync_873.toml`.
- [x] **finger (TCP/79)** — user enumeration and `user@host` relay-bounce
      attempts, logged and refused. Bundled `finger_79.toml`.
- [x] **rpcbind (UDP/111)** — GETPORT/DUMP/CALLIT recon logged; single
      chokepoint enforces "no reply larger than the request". Bundled
      `rpcbind_111.toml`.
- [x] **AMQP 0-9-1 (TCP/5672)** — RabbitMQ mimic capturing SASL
      PLAIN/AMQPLAIN credentials and every method attempted. Bundled
      `amqp_5672.toml`.
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

## What this batch opens up but didn't do

Each of these is now cheap because the machinery exists, and none of them
were in scope for the work that just landed.

- [ ] **Operator-facing severity tuning.** `severity` on a signature is a
      fixed judgement about impact-if-real. A deployment that only cares
      about, say, deserialization has no way to re-rank without editing the
      table.
- [ ] **Operator-supplied exploit signatures.** `SIGNATURES` is a literal
      list in one module. A `--exploit-rules` loader (same shape, from TOML)
      would let deployments add what they're actually seeing without a
      code change.
- [ ] **Cross-session virtual filesystem.** Every telnet connection gets a
      fresh `ShellSession`, so a loader that writes a file in one session
      and executes it in the next sees nothing staged. Keying a VFS by
      source IP with a TTL would catch that pattern — at the cost of
      per-peer state the handler currently doesn't keep.
- [ ] **Shell emulation behind SSH.** The emulator is transport-agnostic
      and already serves two handlers, but the SSH handler stops at the
      banner/KEX. Getting to a shell means implementing real key exchange,
      which is the actual work, not the shell.
- [ ] **Non-HTTP fetching.** The fetcher takes `iocs["urls"]`, which the
      IOC extractor only populates with `http(s)`. Telnet `download_attempt`
      events routinely name tftp and ftp sources that nothing follows up on.
- [ ] **Canary-token alerting.** Tokens are only useful if someone notices
      them being used elsewhere. There is no export of the issued set (they
      are derivable from the seed, but not written anywhere) and no hook for
      an out-of-band alert.
- [ ] **`honeyknot-stats` doesn't know about the new events.** It counts
      them generically under "events by kind" but has no breakdown for
      `exploit_attempt`, `artifact`, or `payload_fetch` the way it does for
      IOCs and samples.
- [ ] **Deception beyond HTTP.** The canary-token idea generalizes — an FTP
      directory listing or an SMB share full of plausible-looking files
      would work the same way and reuse `deception.canary_token`.
