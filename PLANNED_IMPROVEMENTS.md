# PLANNED_IMPROVEMENTS.md

Concrete plan for this pass over honeyknot. 10 improvements to existing
behavior/robustness/UX/docs/tests, then 5 new features. All stdlib-only,
matching the existing asyncio + `ProtocolHandler` idioms.

## Improvements

1. **Expand analyzer magic-byte signatures** (`analyzer.py`). Add Mach-O
   (32/64/fat), 7-Zip, XZ, BZ2, MS-CAB, Android DEX, Windows LNK, Java
   `.class`, WASM, and `#!` shell shebang, plus a Mach-O arch decoder and a
   shebang interpreter extractor. *More captured droppers get identified —
   the core farming mission.*

2. **Broaden IOC extraction** (`ioc.py`). Add Windows LOLBIN downloaders
   (certutil, bitsadmin, `Invoke-WebRequest`/`iwr`, mshta, regsvr32-URL) and
   wire the previously-dead `.onion` and IPv6-literal regexes into
   `extract_iocs` so they surface as `onions` / `ipv6` fields. *Commodity
   Windows/Tor loaders were invisible to triage before.*

3. **Config port-range + duplicate-port validation** (`config.py`). Reject
   ports outside 1..65535 at load and raise a clear error when two handler
   TOMLs claim the same port (silently clobbered in the server dict today).
   *Fail loud at startup instead of losing a listener.*

4. **DRY the capture-finalize pipeline** (`server.py`). Fold the two
   near-identical `_finalize_capture` / `_finalize_datagram` bodies (~90
   lines) into one shared `_finalize_payload(...)` helper. *Single-source the
   analysis/IOC/YARA/meta path so the two transports can't drift.*

5. **Per-connection idle timeout** (`server.py`, `cli.py`, `__init__`). New
   `--conn-idle-timeout` (default 120s, 0 disables) wraps `reader.read` in
   `asyncio.wait_for` so slowloris / idle-hold TCP connections are reaped.
   *Bounds resource cost for an internet-exposed daemon.*

6. **IPv6-safe PCAP** (`pcap.py`, `server.py`). The writer synthesizes IPv4
   framing and silently emits `0.0.0.0` for IPv6 peers, producing corrupt
   captures. Detect a non-IPv4 peer/bind and disable pcap for that session
   (logged once). *No more misleading pcaps.*

7. **`--version` and `--list-protocols` CLI flags** (`cli.py`). Print the
   version (from `__version__`) or the protocol registry grouped by
   transport, then exit. *Basic discoverability/ops UX.*

8. **`run_from_interactive_shell` parity** (`__init__.py`). Forward
   `**daemon_kwargs` so the shell entry point can enable rate limiting,
   yara, pcap, metrics, idle-timeout, etc.; stop documenting the dead
   `thread_count`. *The documented Python-shell path was stuck on 2021
   options.*

9. **Metrics observability additions** (`metrics.py`, `server.py`). Add
   `honeyknot_build_info{version=...}`, `honeyknot_uptime_seconds`, and a
   `honeyknot_bytes_captured_total` counter fed from capture finalize.
   *Dashboards get liveness + throughput, not just event counts.*

10. **Docs sync** (`README.md`, `EVENTS.md`, `ROADMAP.md`, `events.py`).
    Document the new flags, protocols, stats tool, IOC fields, and metrics;
    fix the stale `bytes_out` reference in the `events.py` docstring; mark
    shipped roadmap items. *Keep the docs-as-source-of-truth invariant the
    repo already values.* (CI note: a `.github/workflows` job is already
    present and out of scope to edit — the push token lacks workflow scope.)

## New features

11. **TFTP handler (UDP/69)** — parse RRQ/WRQ, capture the requested
    filename and mode, emit `tftp_request`, reply with an ERROR packet.
    *Mirai/IoT malware fetches payloads over TFTP; the IOC regex already
    hunts `tftp` command lines — now we catch the server side too.*

12. **ADB handler (TCP/5555)** — parse the Android Debug Bridge framing,
    answer `A_CNXN` with a device banner, and capture the `A_OPEN`
    destination (`shell:...` command lines) that ADB.Miner-class botnets
    drop. Emits `adb_connect` / `adb_open`.

13. **LDAP handler (TCP/389)** — minimal BER parser for `bindRequest`
    (capture bind DN + simple password → `credentials`) and `searchRequest`
    (capture baseObject → `ldap_search`), replying with a success
    `bindResponse`. *LDAP is heavily brute-forced; capture the creds.*

14. **NTP handler (UDP/123)** — reply to a standard mode-3 client query with
    a same-size mode-4 server response; refuse and log mode-6/mode-7
    (control / `monlist`) requests without amplifying. *NTP recon logging
    that stays true to the project's amplification-defense posture.*

15. **`honeyknot.stats` offline analyzer** — new module + `honeyknot-stats`
    entry point that reads `events.jsonl` (and rotated backups) and prints
    top peers, top samples, protocol/event breakdown, and aggregated IOCs
    for fast triage without `jq` gymnastics.
