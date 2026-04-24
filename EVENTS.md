# EVENTS.md

Operator reference for events emitted to `logs/events.jsonl`. One JSON
object per line. All events carry the common fields below; event-specific
fields follow.

## Common fields (every event)

| field | type | description |
|---|---|---|
| `ts` | ISO-8601 UTC | microsecond-precision timestamp |
| `event` | string | event kind — see sections below |
| `transport` | `"tcp"` \| `"udp"` \| `"-"` | transport that produced this event (`-` for daemon-level events) |
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
Regex-extracted indicators. One event per session that has any hits; fields can be empty lists.

| field | type | description |
|---|---|---|
| `sha256` | string | |
| `urls` | list[string] | matched HTTP/HTTPS URLs |
| `ips` | list[string] | IPv4 literals (with 0.0.0.0/127.0.0.1/255.255.255.255 filtered) |
| `downloads` | list[string] | matched wget/curl/tftp/fetch/busybox invocations |
| `shell` | list[string] | matched shell pivots (chmod +x, base64 -d, eval, /tmp/*, nc, python -c, powershell -enc) |

### `yara_match`
Only emitted if `--yara-rules` is set and `yara-python` is installed.

| field | type | description |
|---|---|---|
| `sha256` | string | |
| `matches` | list[object] | each match has `{"rule", "tags", "meta", "strings"}` |

## Handler-level (`protocol` events)

Every `protocol` event carries a `name` field identifying the specific
handler signal. A `credentials` event is one common shape; each handler
documents its own here.

### `protocol / credentials`
Captured auth material. Emitted by the handlers listed.

| field | type | source |
|---|---|---|
| `service` | string | which protocol, e.g. `"ftp"`, `"telnet"`, `"mqtt"` |
| `username` | string | FTP, Telnet, MySQL, Postgres, IMAP, POP3, MQTT |
| `password` | string | same as above, cleartext |
| `mechanism` | string \| omitted | `"PLAIN"`, `"APOP"` |
| `authzid` | string \| omitted | SASL PLAIN authzid |
| `digest` | string \| omitted | POP3 APOP digest hex |
| `challenge` | string \| omitted | POP3 APOP challenge text (for offline recovery) |
| `client_id` | string \| omitted | MQTT CONNECT client identifier |
| `auth_response_hex` | string \| omitted | MySQL authentication response bytes |
| `challenge_hex` | string \| omitted | MySQL challenge bytes (for offline cracking) |
| `database` | string \| omitted | MySQL/Postgres database name |

### `protocol / shell_command`
Telnet handler. Fake-shell commands typed after a captured login.

| field | type |
|---|---|
| `service` | `"telnet"` |
| `command` | string |

### `protocol / command`
FTP handler. LIST/NLST/STOR/APPE/RETR/DELE attempts against the unavailable data channel.

| field | type |
|---|---|
| `service` | `"ftp"` |
| `command` | string |
| `arg` | string |

### `protocol / http_request`
HTTP handler. One per fully-reassembled request.

| field | type |
|---|---|
| `method`, `path`, `version` | string |
| `body_bytes` | int |
| `content_type` | string |

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
