# EVENTS.md

Operator reference for events emitted to `logs/events.jsonl`. One JSON
object per line. All events carry the common fields below; event-specific
fields follow.

## Common fields (every event)

| field | type | description |
|---|---|---|
| `ts` | ISO-8601 UTC | microsecond-precision timestamp |
| `event` | string | event kind — see sections below |
| `transport` | `"tcp"` \| `"udp"` \| `"-"` | transport that produced this event (`-` for daemon-level events, and for payloads honeyknot fetched itself — those never crossed a listener) |
| `port` | int | honeyknot port the event happened on (`0` for daemon-level) |
| `protocol` | string | handler name, e.g. `"ssh"`, `"regex"`, `"dns"` |
| `peer` | `"<ip>:<port>"` | remote party; omitted on daemon-level events |

## Connection lifecycle

### `connect` (TCP only)
Emitted after accept. Blocked by rate limiter → no `connect`; see `rate_limited`.

| field | type | description |
|---|---|---|
| `capture` | string \| null | path to the `logs/raw/*.bin` file for this session |

### `close` (TCP only)
Emitted after the handler returns and the socket is torn down. Paired 1:1 with `connect`.

| field | type | description |
|---|---|---|
| `bytes_in` | int | total bytes read from the peer (may exceed the capture cap) |
| `sha256` | string \| null | SHA-256 of the captured bytes (the correlation key) |

### `datagram` (UDP only)
One per datagram received. No lifecycle — UDP is stateless.

| field | type | description |
|---|---|---|
| `bytes` | int | datagram size |
| `capture` | string \| null | path to the `logs/raw/*_udp.bin` file |
| `sha256` | string \| null | SHA-256 of the datagram |

### `rate_limited`
Emitted when the per-source token bucket is empty. No handler invocation or raw capture happens.

No event-specific fields.

## Analysis pipeline

All analysis events carry `sha256`, so joining them against `close` / `datagram` by that key gives a per-session picture.

### `sample_new`
Fires the first time a given `sha256` is ever seen. Re-hits of the same payload don't emit this.

| field | type | description |
|---|---|---|
| `sha256` | string | digest of the payload |
| `bytes` | int | size of the stored sample |

### `analyzer_hit`
Magic-byte match somewhere in the captured bytes. See `honeyknot/analyzer.py` for the signature list.

| field | type | description |
|---|---|---|
| `sha256` | string | |
| `result` | object | `{"type": "ELF"\|"PE/EXE"\|"PDF"\|..., "offset": int, ...type-specific...}` |

### `ioc`
Regex-extracted indicators. One event per session that has any hits. Empty
categories are omitted from the object, so only the non-empty keys appear.

| field | type | description |
|---|---|---|
| `sha256` | string | |
| `urls` | list[string] | matched HTTP/HTTPS URLs |
| `ips` | list[string] | IPv4 literals (with 0.0.0.0/127.0.0.1/255.255.255.255 filtered) |
| `ipv6` | list[string] | IPv6 literals (loopback/unspecified/link-local filtered) |
| `onions` | list[string] | Tor v2/v3 `.onion` hidden-service addresses (lowercased) |
| `downloads` | list[string] | matched wget/curl/tftp/fetch/scp/busybox invocations and Windows LOLBINs (certutil, bitsadmin, `Invoke-WebRequest`/`iwr`, mshta, regsvr32) |
| `shell` | list[string] | matched shell pivots (chmod +x, base64 -d, eval, /tmp/*, nc, python -c, powershell -enc) |

### `exploit_attempt`
What the attacker was *trying to do*, from the signature table in
`honeyknot/exploits.py`. Honeyknot serves nothing real, so a hit is always
an attempt: it says these bytes match the shape of a known exploit, never
that anything was exploited. Signatures are matched against the head of the
buffer (256 KB) plus its percent-decoded and gzip/zlib/base64-peeled
variants, and each signature reports at most once per payload.

| field | type | description |
|---|---|---|
| `sha256` | string \| null | |
| `hits` | list[object] | one per signature, most severe first: `{"id", "title", "category", "severity", "match", "offset"}`. `match` is the matched span, truncated to 160 chars with control bytes escaped |
| `exploit_ids` | list[string] | distinct `id`s: a CVE (`CVE-2021-44228`) where the mapping is unambiguous, otherwise a technique slug (`sqli-union`, `webshell-php`). Slugs never start with `CVE-`, so a prefix test splits the two classes |
| `categories` | list[string] | distinct categories: `rce`, `traversal`, `webshell`, `sqli`, `deserialization`, `auth-bypass`, `recon`, … |
| `severity` | string | highest present, one of `critical`/`high`/`medium`/`low`/`info`. This is impact *if the payload had landed on a real service* — not confidence in the match |
| `count` | int | number of hits |

Handlers can also emit an exploit verdict mid-session — JDWP recognizing an
`invokeMethod`, RMI recognizing a gadget chain — for exploits identified by
protocol structure rather than by a byte pattern. Those arrive wrapped as
`protocol` / `exploit_attempt` and carry **the same fields**, built by
`exploits.as_event_fields`, so one filter finds every exploit event
regardless of which layer spotted it:

```sh
jq -r 'select(.event == "exploit_attempt" or .name == "exploit_attempt")
       | [.ts, .peer, .severity, (.exploit_ids | join(","))] | @tsv' events.jsonl
```

The handler-emitted ones add their own context fields alongside (RMI adds
`indicators`, HTTP adds `method`/`path`, telnet adds `command`).

### `yara_match`
Only emitted if `--yara-rules` is set and `yara-python` is installed.

| field | type | description |
|---|---|---|
| `sha256` | string | |
| `matches` | list[object] | each match has `{"rule", "tags", "meta", "strings"}` |

### `artifact`
A file a handler reconstructed out of a session: an ELF rebuilt from an
`echo -ne '\x7fELF...' >> .s` loader, a heredoc script, a `curl ... | sh`
body, the output of a command run through the HTTP deception layer. Those
bytes are already in the raw capture, but tangled up with protocol framing;
storing the extracted file on its own means it hashes to the same digest as
the identical payload delivered any other way, so the sample store
deduplicates across transports.

An artifact runs the *whole* pipeline — analyzer, IOC, YARA, exploits — so
it gets its own `analyzer_hit` / `ioc` / `sample_new` / `exploit_attempt`
events under the artifact's `sha256`, not the enclosing session's.

| field | type | description |
|---|---|---|
| `name` | string | the path or label the attacker used, e.g. `/tmp/.s`, `piped-script.sh` |
| `kind` | string | `"shell_upload"` (telnet fake shell) or `"web_exec"` (HTTP deception layer) |
| `bytes` | int | size of the reconstructed file |
| `sha256` | string \| null | digest, or null if the file was under 4 bytes |

### `payload_fetch`
Only emitted when `--fetch-payloads` is set. One per URL honeyknot actually
attempted, including attempts whose destination was refused — a URL skipped
because it was already fetched, or because the process-lifetime budget is
spent, emits nothing at all. `transport` is `"-"`;
`port`, `protocol` and `peer` are inherited from the session whose `ioc`
event produced the URL, so the join back to the attacker still works. The
downloaded bytes then produce their own `sample_new` / `analyzer_hit` /
`ioc` / `exploit_attempt` events, also with `transport: "-"`.

| field | type | description |
|---|---|---|
| `url` | string | the attacker-supplied URL |
| `status` | int \| null | HTTP status; null when the fetch never completed |
| `bytes` | int | body size stored (0 on failure) |
| `sha256` | string \| null | digest of the body |
| `content_type` | string \| null | response `Content-Type` |
| `error` | string \| null | why it failed or was refused — `refusing non-public destination 10.0.0.5`, `dns failure: ...`, `truncated at max_bytes`, or `repr(exc)` |
| `elapsed_ms` | int | wall-clock time for the fetch |

## Handler-level (`protocol` events)

Handler signals are not their own event kind. `server.py:_emit_protocol`
wraps all of them: `event` is the literal string `"protocol"`, and the
handler's signal name lands in a `name` field alongside the usual
`transport` / `port` / `protocol` / `peer`. That's why the headings below
read `protocol / <name>`, and why the filter for any of them is:

```bash
jq 'select(.event == "protocol" and .name == "credentials")' logs/events.jsonl
```

Because the sink owns those five keys, `name`, `transport`, `port`,
`protocol` and `peer` are reserved — a handler passing one as a field gets a
TypeError at emit time. Hence `command_name` on `jdwp_command`, `method` on
`amqp_method`, `protocol_name` on `rmi_connect`, and `type_name` on
`rmi_message`.

### `protocol / credentials`
Captured auth material. Emitted by the handlers listed.

| field | type | source |
|---|---|---|
| `service` | string | which protocol: `"ftp"`, `"telnet"`, `"mqtt"`, `"ldap"`, `"rtsp"`, `"socks5"`, `"amqp"`, `"rsync"`, `"http"`, … |
| `username` | string | FTP, Telnet, MySQL, Postgres, IMAP, POP3, MQTT, RTSP, SOCKS5, AMQP, rsync, HTTP; LDAP bind DN |
| `password` | string \| null | same as above, cleartext. Null where the scheme never sends one (RTSP Digest, rsync challenge-auth) |
| `method` | string \| omitted | LDAP auth type (`"simple"`, `"sasl"`) |
| `mechanism` | string \| omitted | `"PLAIN"`, `"APOP"`; AMQP SASL mechanism (`"PLAIN"`, `"AMQPLAIN"`) |
| `auth` | string \| omitted | RTSP `"basic"`/`"digest"`, rsync `"challenge"`, HTTP deception `"basic"`/`"form"` |
| `authzid` | string \| omitted | SASL PLAIN authzid |
| `digest` | string \| omitted | POP3 APOP digest hex |
| `challenge` | string \| omitted | POP3 APOP challenge text, or the rsync challenge we issued (both for offline recovery) |
| `response` | string \| omitted | RTSP Digest response hash, or the rsync auth response — crackable offline against `challenge` |
| `realm`, `nonce`, `uri` | string \| omitted | RTSP Digest parameters as the client sent them |
| `attempt` | int \| omitted | Telnet: which login attempt this was on the connection |
| `path` | string \| omitted | HTTP deception: the login/manager path the credentials were posted to |
| `client_id` | string \| omitted | MQTT CONNECT client identifier |
| `auth_response_hex` | string \| omitted | MySQL authentication response bytes |
| `challenge_hex` | string \| omitted | MySQL challenge bytes (for offline cracking) |
| `database` | string \| omitted | MySQL/Postgres database name |

### `protocol / shell_command`
Telnet handler. One per command line typed after a captured login. The
emulated shell that answers it emits its own events too — see
*Emulated shell* below.

| field | type |
|---|---|
| `service` | `"telnet"` |
| `command` | string (truncated to 500 chars) |

### `protocol / command`
FTP handler. LIST/NLST/STOR/APPE/RETR/DELE attempts against the unavailable data channel.

| field | type |
|---|---|
| `service` | `"ftp"` |
| `command` | string |
| `arg` | string |

### `protocol / http_request`
HTTP handler. One per fully-reassembled request, emitted before any response
is chosen — so it fires for deception routes, rule matches and defaults alike.

| field | type |
|---|---|
| `method`, `path`, `version` | string |
| `body_bytes` | int |
| `user_agent` | string \| null |
| `content_type` | string \| null |

### `protocol / h2_preface`
HTTP/2 preface observed (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`). We reply 505. No body.

### `protocol / vnc_version`, `protocol / vnc_auth_attempt`
VNC handler. `vnc_version` carries the client's banner string;
`vnc_auth_attempt` carries `challenge` and `response` (16-byte DES) as hex.

### `protocol / sip_request`
SIP handler.

| field | type |
|---|---|
| `method` | string |
| `from_`, `to` | string |
| `user_agent` | string |
| `auth` | string | raw Authorization header if present |

### `protocol / ipmi_ping`
IPMI handler. `tag` is the RMCP message tag byte.

### `protocol / coap_request`
CoAP handler. `method`, `path`, `msg_id`, `token` (hex).

### `protocol / modbus_request`
Modbus handler.

| field | type |
|---|---|
| `function` | int | Modbus function code |
| `unit` | int | unit identifier |
| `transaction` | int | transaction id |
| `payload` | string | hex of the PDU minus the function byte |

### `protocol / mqtt_publish`
MQTT handler. PUBLISH packet decoded.

| field | type |
|---|---|
| `topic` | string |
| `qos` | int |
| `packet_id` | int \| null |
| `body_bytes` | int |
| `body` | string | hex of the payload (see samples module for raw retrieval) |

### `protocol / s7_request`
S7 handler. `rosctr`, `function`, `params` (hex).

### `protocol / pop3_post_auth_attempt`
POP3 handler. A STAT/LIST/UIDL/RETR/DELE/TOP attempt without auth.

### `protocol / bacnet_request`
BACnet handler. `service` is a label (`"Who-Is"`, `"0x12"`, …); `payload` is hex.

### `protocol / wsd_probe`
WS-Discovery handler. `action` and `message_id` from the SOAP envelope.

### `protocol / tls_sni`
Emitted when a TLS ClientHello is parsed out of a non-TLS protocol's
post-handshake captured bytes (today: the RDP handler).

| field | type |
|---|---|
| `source` | string | which handler produced this (`"rdp"`) |
| `sni` | string | server_name extension hostname |

### `protocol / tftp_request`
TFTP handler. A read (RRQ) or write (WRQ) request; we log it and reply ERROR.

| field | type |
|---|---|
| `op` | `"RRQ"` \| `"WRQ"` |
| `filename` | string |
| `mode` | string (`"octet"`, `"netascii"`, …) |

### `protocol / ntp_request`, `ntp_control`, `ntp_private`
NTP handler. `ntp_request` is a normal mode-3 client query (answered with a
same-size mode-4 reply). `ntp_control` (mode 6) and `ntp_private` (mode 7,
the `monlist` amplification vector) are logged and dropped without replying.

| field | type |
|---|---|
| `version` | int | NTP version from the request |
| `mode` | int | present on `ntp_control` / `ntp_private` |

### `protocol / adb_connect`, `adb_open`
ADB handler (Android Debug Bridge, TCP/5555). `adb_connect` is the `A_CNXN`
handshake; `adb_open` captures each `A_OPEN` destination — the `shell:`
command line ADB.Miner-class botnets drop.

| field | type |
|---|---|
| `system` | string | client system-identity banner (on `adb_connect`) |
| `version`, `maxdata` | int | ADB protocol version / max payload (on `adb_connect`) |
| `destination` | string | the opened stream target, e.g. `"shell:..."` (on `adb_open`) |

### `protocol / ldap_search`
LDAP handler. A `searchRequest` baseObject. (Bind credentials arrive as a
`credentials` event with `service = "ldap"`.)

| field | type |
|---|---|
| `base` | string | search baseObject DN |

### `protocol / exploit_attempt`
A handler classifying something mid-session, before the capture-finalize
pipeline gets a look. Fields are identical to the top-level
`exploit_attempt` — every emitter goes through `exploits.as_event_fields` —
so a single filter covers both. Two kinds of emitter:

- **HTTP** (per request) and **Telnet** (per command line) run the same
  `honeyknot.exploits` signature table as the pipeline event.
- **JDWP** and **RMI** recognize an exploit from protocol *structure*
  rather than a byte pattern — an `invokeMethod` call, a JRMP gadget
  chain — and report it as a synthesized hit in the same shape.

The only difference from the top-level event is that these have no
`sha256`: they fire mid-session, before the capture is hashed.

| field | type | source |
|---|---|---|
| `hits` | list[object] | all — same objects as the top-level event |
| `exploit_ids`, `categories`, `severity`, `count` | | all |
| `method`, `path` | string | HTTP |
| `command` | string | Telnet, first 200 chars of the line |
| `id` | string | JDWP `"jdwp-rce"`, RMI `"java-deserialization"` |
| `title` | string | JDWP `"jdwp invokeMethod"`, RMI `"JRMP serialized gadget"` |
| `severity` | string | JDWP/RMI: always `"critical"` |
| `indicators` | list[string] | RMI: which gadget markers were found in the stream |

### Emulated shell
`honeyknot.shell` answers commands for the telnet handler and for the HTTP
deception layer's command-execution routes. Nothing is executed — every
answer comes from a table — but the commands attempted are the point. Via
telnet these all carry `service: "telnet"`; via HTTP they do not.

Reconstructed files (echo-loader binaries, heredoc bodies, `| sh` inputs)
are not in these events: they arrive as top-level `artifact` events.

| name | fields |
|---|---|
| `busybox_probe` | `applet` (string) — the random token from `/bin/busybox <TOKEN>`, the BusyBox fingerprint check. Its presence means a Mirai-class loader is walking its recon script |
| `download_attempt` | `tool` (`"wget"`/`"curl"`/`"ftpget"`/`"tftp"`), `urls` (list[string]), `host` (string \| null), `output` (string \| null, the `-O` target), `argv` (list[string], first 12). `tftp` sends `remote` instead of `urls`/`output` |
| `file_write` | `path` (absolute, string), `bytes` (int, this write), `total` (int, file size so far), `append` (bool) |
| `payload_exec` | `path` (string as typed), `resolved` (absolute), `staged` (bool — true if we saw the file being written earlier this session), `argv` (list[string], first 8) |
| `script_exec` | `bytes` (int), `preview` (string, first 200 chars) — something was piped into `sh`/`bash` |
| `chmod` | `targets` (list[string], first 8), `argv` (list[string], first 8) |
| `file_delete` | `argv` (list[string], first 8) |
| `file_copy` | `src`, `dst` (string) |
| `process_kill` | `argv` (list[string], first 12) — the competitor list is a good family fingerprint |
| `package_install` | `argv` (list[string], first 12) — apt/yum/apk/opkg |
| `crontab` | `argv` (list[string], first 8) — a persistence attempt (`crontab -l` is answered, not reported) |

### HTTP deception layer
Emitted by `honeyknot.deception` through the HTTP handler when a request
hits a vulnerable-looking route. Every secret in these responses is a
deterministic canary token derived from `[http] canary_seed` — see
`deception.py` for why they are shaped to look real.

| name | fields |
|---|---|
| `secret_served` | `artifact` (`"dotenv"`, `"git_config"`, `"aws_credentials"`, `"wp_config"`, `"actuator_env"`), `path` (string). A hit here means canary credentials are now in the attacker's hands — if they surface anywhere later, that's the provenance |
| `web_command` | `vector` (`"webshell"` or `"shellshock"`), `path` (string), `command` (string, first 500 chars). The command is then run through the shell emulator, so its own shell events follow |
| `container_create` | `image`, `cmd`, `entrypoint`, `binds`, `privileged`, `network_mode` (all straight out of the posted Docker spec, null when absent), `bytes` (int). The spec names the miner image and any host mounts they meant to escape through |
| `container_start` | `path` (string) — the `/containers/<id>/start\|restart\|kill` route hit |
| `container_exec` | `cmd` (from the exec spec), `path` (string) |

### Proxy abuse (`socks` and the HTTP `CONNECT` path)
We complete the handshake, report success, and never open a socket. The
destination states the intent outright: 25/587 is a spam relay test, a
vendor's own checker URL is a durable attribution artifact.

| name | fields |
|---|---|
| `proxy_request` | `version` (`4` or `5` as int from SOCKS, the string `"http"` from a `CONNECT`), `command` (`"CONNECT"`/`"BIND"`/`"UDP_ASSOCIATE"`), `dest_host` (string), `dest_port` (int \| null), `userid` (string, SOCKS4 only) |
| `proxy_payload` | `bytes` (int), `preview` (string, first 200 bytes with non-printables dotted). Emitted once, for the first chunk pushed into the tunnel |
| `proxy_http_request` | `method`, `target` (string) — the SOCKS handler recognising HTTP inside the tunnel |

### `protocol / rtsp_request`
RTSP handler. One per request. The URL is a vendor fingerprint
(`/onvif/device_service`, `/cam/realmonitor?channel=1`) — it names the
exploit kit knocking. Credentials arrive separately as a `credentials`
event with `service = "rtsp"`.

| field | type |
|---|---|
| `method` | string |
| `url` | string |
| `cseq` | string \| null |
| `user_agent` | string |

### `protocol / jdwp_handshake`, `jdwp_command`, `jdwp_class_lookup`, `jdwp_event_request`, `jdwp_invoke`
JDWP handler (TCP/8000). An exposed Java debugger is unauthenticated RCE, so
the sequence here *is* the attack: handshake → look up
`Ljava/lang/Runtime;` → plant a breakpoint → `invokeMethod` with a command
line. `jdwp_invoke` is the one that carries the payload.

| field | type | description |
|---|---|---|
| `bytes` | int | `jdwp_handshake`: bytes echoed back |
| `command_set`, `command` | int | numeric command-set / command |
| `command_name` | string | resolved name, e.g. `"VirtualMachine.Version"` (`name` is reserved by the sink) |
| `id` | int | JDWP packet id |
| `data_bytes` | int | payload size |
| `signature` | string | `jdwp_class_lookup`: the requested class signature |
| `event_kind`, `suspend_policy` | int | `jdwp_event_request`: the breakpoint being planted |
| `strings` | list[string] | `jdwp_invoke`: printable runs scraped out of the invoke data — the command line falls out here |

### `protocol / rmi_connect`, `rmi_message`, `java_serialized`
RMI registry handler (TCP/1099). Nothing is ever deserialized; the Call body
is treated as an opaque blob and mined for class names.

| field | type | description |
|---|---|---|
| `jrmp_protocol` | string | hex byte, e.g. `"0x4b"` |
| `protocol_name` | string | `"StreamProtocol"`, `"SingleOpProtocol"`, `"MultiplexProtocol"`, `"unknown"` |
| `version` | int | JRMP version from the header |
| `type` | string | `rmi_message`: hex message type, e.g. `"0x50"` |
| `type_name` | string | `"Call"`, `"Ping"`, `"DgcAck"`, … |
| `bytes` | int | body size (0 for the single-byte messages) |
| `offset` | int | `java_serialized`: where the `\xac\xed\x00\x05` stream header sat in the body |
| `strings` | list[string] | printable runs from the first 4 KB of the stream — serialized class names and JNDI/LDAP URLs land here |

A `java_serialized` whose strings contain a known gadget marker also emits
`protocol` / `exploit_attempt` with `exploit_ids = ["java-deserialization"]`
plus an `indicators` list naming the markers that hit.

### `protocol / zookeeper_connect`, `zookeeper_request`, `zookeeper_command`
ZooKeeper handler (TCP/2181).

| field | type | description |
|---|---|---|
| `protocol_version`, `timeout_ms`, `session_id` | int \| null | `zookeeper_connect`: parsed from the ConnectRequest; null where the frame was too short |
| `xid`, `opcode` | int \| null | `zookeeper_request` |
| `opcode_name` | string | `"create"`, `"getData"`, `"ping"`, `"multi"`, `"unknown"` |
| `bytes` | int | request frame size |
| `command` | string | `zookeeper_command`: the four-letter word (`ruok`, `stat`, `envi`, `mntr`, …) |
| `known` | bool | whether it is one we answer; unknown words get the real server's whitelist refusal |

### `protocol / rsync_module`, `rsync_list`, `rsync_args`
rsync daemon handler (TCP/873). Auth credentials arrive as a `credentials`
event with `service = "rsync"`.

| field | type | description |
|---|---|---|
| `module` | string \| null | the module name requested |
| `known` | bool | whether it is in our advertised list |
| `modules` | list[string] | `rsync_list`: the module names we advertised in response to `#list` |
| `args` | list[string] | `rsync_args`: the NUL-separated argument vector, capped at 50 entries of 200 chars. `--sender` in here means they are pulling data *out*; its absence means they are pushing files *in* |

### `protocol / finger_query`, `finger_relay`
finger handler (TCP/79). Nearly-extinct protocol, so any query is pure
signal: the usernames tell you which credential list is being worked from.

| field | type | description |
|---|---|---|
| `query` | string | the whole query line, stripped to printable ASCII |
| `verbose` | bool | the `/W` flag was present |
| `user` | string | the username asked about (empty for a bare listing request) |
| `target_host` | string | `finger_relay` only: the host in a `user@host` bounce attempt. We log it and refuse; nothing is ever forwarded |

### `protocol / rpc_call`, `rpc_getport`, `rpc_dump_refused`, `rpc_callit`
rpcbind/portmap handler (UDP/111). `rpc_call` fires for every well-formed
ONC RPC v2 call; the other three add detail for the procedures worth
detail. No reply is ever larger than the request that triggered it, and
`DUMP`/`CALLIT` — the two amplification vectors — get an empty list and
silence respectively.

| field | type | description |
|---|---|---|
| `xid` | int | RPC transaction id |
| `program`, `version`, `procedure` | int | from the call header (`rpc_callit`: the *inner* target being proxied) |
| `program_name` | string | `"portmapper"`, `"nfs"`, `"mountd"`, `"status"`, `"unknown"`, … |
| `procedure_name` | string | `"NULL"`, `"GETPORT"`, `"DUMP"`, `"CALLIT"`, … |
| `bytes` | int | datagram size |
| `query_program`, `query_version` | int | `rpc_getport`: the service being looked up |
| `query_program_name` | string | resolved name for `query_program` |
| `query_protocol` | string | `"tcp"`, `"udp"`, or the raw number as a string |

### `protocol / amqp_client`, `amqp_open`, `amqp_channel_open`, `amqp_method`, `amqp_bad_protocol_header`
AMQP 0-9-1 handler (TCP/5672), presenting as RabbitMQ. Credentials arrive as
a `credentials` event with `service = "amqp"`; we accept whatever turns up,
because a client that gets in proceeds to declare queues and that says more
than a rejection.

| field | type | description |
|---|---|---|
| `product`, `version`, `platform` | string | `amqp_client`: the client library's self-declared properties, from Connection.StartOk |
| `vhost` | string | `amqp_open`: requested virtual host |
| `channel` | int | channel number |
| `class_id`, `method_id` | int | `amqp_method`: numeric method identity |
| `method` | string | resolved name, e.g. `"Queue.Declare"` (`name` is reserved by the sink) |
| `bytes` | int | method frame payload size |
| `header_hex` | string | `amqp_bad_protocol_header`: the 8-byte header offered, which fingerprints the client (AMQP 1.0, 0-8, or garbage) |

## Daemon-level (`transport: "-"`, `port: 0`)

### `port_down`
Emitted by the supervisor when a serve task exits with an exception.

| field | type |
|---|---|
| `port` | int | the port that dropped (even though the top-level `port` field is the protocol-level one, here they align) |
| `error` | string | `repr(exc)` |

### `port_up`
Emitted when the supervisor successfully re-binds after a `port_down`.

### `retention_sweep`
Emitted by the raw-dir retention task after a non-trivial sweep.

| field | type |
|---|---|
| `deleted` | int | files pruned this cycle |
| `total_bytes` | int | total after pruning |

### `config_reload`
Emitted on SIGHUP after reconciling the handler directory.

| field | type |
|---|---|
| `added` | list[int] | newly-bound ports |
| `removed` | list[int] | closed ports |
| `changed` | list[int] | ports whose config changed (stop+start) |
| `error` | string \| omitted | set when the reload failed entirely (bad TOML etc.) |

## Correlation patterns

- **"what did this attacker drop?"** — filter events by `peer`, find all `close`/`datagram` events, collect the `sha256` values, look up the files in `logs/samples/<xx>/<sha>.bin` and their `.meta.json` sidecars.
- **"what's in sample X?"** — filter `events.jsonl` for `sha256 == X`. The `analyzer_hit`, `ioc`, and `yara_match` events for that digest are the capture-time analysis; the `.meta.json` next to the sample has aggregated `first_seen`/`last_seen`/`hit_count`/distinct `peers`.
- **"who's brute-forcing us?"** — `rate_limited` events by `peer`, or `protocol` events with `name == "credentials"` grouped by `peer`.
- **"what ICS recon have we caught?"** — filter by `protocol in {"modbus", "s7", "bacnet"}`.
- **"what was this attacker trying to exploit?"** — `exploit_attempt` events by `peer`, reading `exploit_ids`. Remember there are two sources: the top-level event (whole capture, has `sha256`) and the `protocol`-wrapped one (per request / per command, no `sha256`). Both carry identical fields, but filtering on `.event == "exploit_attempt"` alone silently drops the second kind — match `.name` too.
- **"which of my canary tokens have been handed out?"** — `protocol` events with `name == "secret_served"`, grouped by `artifact`. If one of those strings later shows up in a paste dump or an auth log on a real system, this is when and to whom it leaked.
- **"did the loader actually drop something?"** — `artifact` events give you the reconstructed file's `sha256` directly; the matching `sample_new` tells you whether it was new to the store.
