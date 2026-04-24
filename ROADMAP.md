# ROADMAP.md

Planned work and known gaps, grouped by area and prioritized within each
group. See `REWORK.md` for the historical phase plan that got us here.

## Status as of this file

- 17 protocol handlers: regex + 6 stateful TCP (ssh, smtp, ftp, telnet,
  redis, vnc) + 3 binary TCP (smb, mssql, rdp) + 6 UDP
  (dns, snmp, ssdp, netbios_ns, chargen, memcached) + proper http
- Single asyncio event loop, one process
- Raw per-session captures, content-addressed sample store (SHA-256), JSONL
  event log with size-based rotation, IOC extraction at capture time
- 124 tests passing, ruff clean

## Capture quality & analysis

- [ ] **YARA integration.** Optional — only run if `yara-python` is installed.
      Emit `yara_match` events with rule name + meta. Best single addition
      for turning the sample store into a usable corpus.
- [ ] **Per-source rate limiting.** Token bucket keyed by peer IP; drop (or
      tarpit) above N connections/sec and M bytes/sec. Without this, a
      single aggressive scanner fills the disk.
- [ ] **Transparent decompression in the IOC extractor.** A lot of droppers
      arrive base64-encoded or gzip-wrapped; unpack one layer before
      running regexes. Currently a gzip dropper bypasses IOC extraction
      entirely.
- [ ] **PCAP-ng export.** Phase 4 item 12, deferred. Lets existing malware
      tooling (Zeek, Suricata, wireshark session reassembly) ingest the
      capture directly instead of going through our raw `.bin` format.
- [ ] **Raw-dir retention / sweeper.** `logs/raw/` grows unboundedly. Need
      either a size-based sweeper task or documented external cron. Low
      urgency now that `samples/` carries the unique content — raw exists
      only for session ordering.
- [ ] **Sample metadata sidecar.** Alongside `samples/<xx>/<sha>.bin`, write
      `<sha>.meta.json` with first-seen timestamp, hit count, top peers,
      extracted IOCs aggregated. Avoids having to replay `events.jsonl` to
      answer "what do we know about this sample?"

## Missing high-value protocols

- [ ] **SIP (UDP/5060)** — VoIP reconnaissance is constant traffic.
- [ ] **IPMI (UDP/623)** — credential spray target with known CVEs.
- [ ] **Modbus (TCP/502)** + **S7 (TCP/102)** + **BACnet (UDP/47808)** — ICS
      recon; high-signal attackers if any show up at all.
- [ ] **CoAP (UDP/5683)** and **MQTT (TCP/1883, 8883)** — IoT botnet recon.
- [ ] **WS-Discovery (UDP/3702)** — SOAP-over-UDP amplification target;
      Shodan-visible.
- [ ] **Telnet over TLS (TCP/992)**, **DNS-over-TLS (TCP/853)**,
      **MySQL (TCP/3306)**, **Postgres (TCP/5432)**, **IMAP (TCP/143/993)**,
      **POP3 (TCP/110/995)** — all regularly probed, none implemented.
- [ ] **HTTPS coverage for the new HTTP handler.** The HTTP handler currently
      composes with `type = "https"` via `asyncio.start_server`'s ssl
      parameter, but this path is **not** verified by smoke test — do it.

## Operational readiness

- [ ] **Privilege drop.** Bind sockets as root, then `os.setuid` /
      `os.setgid` to an unprivileged user before `serve_forever`. Add a
      `--run-as` CLI flag. Without this, a handler bug on port 22 gives
      the attacker a root process.
- [ ] **Prometheus metrics endpoint.** Bind `127.0.0.1:<port>` with a
      tiny text-format exporter: connections-per-port, unique samples,
      analyzer hits, IOC events, rotations, write errors. Cheap
      observability, huge operational value.
- [ ] **`systemd` unit file** under `contrib/` with
      `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `NoNewPrivileges=yes`,
      `ProtectSystem=strict`, `PrivateTmp=yes`. Pairs with privilege drop.
- [ ] **Dockerfile** (multi-stage, distroless final) + `docker-compose.yml`
      demoing handler volume mount and log-volume persistence.
- [ ] **Handler supervision / restart.** An exception inside `on_connect`
      of one protocol currently just logs and drops the connection —
      that's fine. But a persistent bug that makes `serve_forever` raise
      would silently leak the port. Wrap `serve_tasks` with restart-on-
      failure logic and emit a `port_down` event.
- [ ] **Back-pressure on slow clients.** `asyncio.StreamWriter.write` is
      unbounded; a client that refuses to read our response grows the
      write buffer until OOM. Call `writer.set_write_buffer_limits(high,
      low)` on accept and drop on high-water hit.
- [ ] **SIGHUP reload.** Reload handler TOMLs without restarting the
      daemon. Useful for tuning rule sets under live traffic.

## Protocol / code correctness gaps

- [ ] **Binary frames logged as text.** SMB and RDP `ctx.request_logger.info`
      calls embed hex blobs into the rotating per-port log, which is
      painful to grep. Either emit only a hex digest + length, or route
      binary traffic to the raw sink only.
- [ ] **No handler-isolation lint.** A handler that writes to `self.foo`
      instead of `ctx.state["foo"]` would silently leak between sessions.
      Add a lightweight ast-based lint pass in CI.
- [ ] **No asyncio-level integration tests.** Every handler test uses a
      fake `StreamWriter`. Add a few that go through a real
      `asyncio.start_server` + `asyncio.open_connection` to catch
      wire-format regressions (we caught two of those only via live
      smoke scripts).
- [ ] **HTTP handler: HTTP/2 rejection.** If a client opens with an
      HTTP/2 preface (`PRI * HTTP/2.0...`), we return 400 — that's
      correct, but we should log it as a distinct `h2_preface` event
      so ops can see h2 scanners landing.
- [ ] **RDP: post-confirm captured bytes contain a TLS ClientHello we
      parse nothing from.** Quick win: parse SNI out of the ClientHello
      and emit it as a `tls_sni` event for fingerprinting.

## Small polish / debt

- [ ] `handlers/` lacks TOMLs for some of the protocols we implemented
      on purpose (chargen, memcached, netbios_ns, ssdp, snmp are all
      shipped — but worth double-checking the bundled set matches what
      users are likely to enable by default).
- [ ] `logs/` is in the repo as a directory with some old root-owned
      files; add a `logs/.gitkeep` and put `logs/*` in `.gitignore`.
- [ ] The regex handler still decodes the full incoming chunk as UTF-8
      before matching; for partly binary protocols this wastes CPU.
      Consider matching against bytes regex directly.
- [ ] CI: there is no CI configured. A GitHub Actions workflow running
      `ruff` + `pytest` on push would be ~20 lines of YAML.
- [ ] Publish to PyPI as `honeyknot`, so users can `pipx install honeyknot`
      instead of running from a clone.
