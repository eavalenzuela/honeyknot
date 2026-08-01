"""Java RMI registry honeypot on TCP/1099 — a deserialization sinkhole.

Port 1099 is where ysoserial payloads go to die. The RMI registry accepts a
serialized Java object graph off the wire and calls `readObject` on it, which
is the whole CommonsCollections / TemplatesImpl gadget-chain class of bugs, and
the same port doubles as a JNDI endpoint for the Log4Shell second stage
(`jndi:rmi://attacker/Exploit`). Nobody scans 1099 by accident.

We never deserialize anything — we cannot, and would not want to. We complete
the JRMP handshake so the client commits to sending its payload, then treat the
Call body as an opaque blob: find the `\\xac\\xed\\x00\\x05` stream header, scrape
the printable runs (serialized class names are stored as plain UTF strings, so
`org.apache.commons.collections.functors.InvokerTransformer` or an LDAP URL
falls right out), and flag the known gadget markers. The full byte stream is
kept by the capture layer for offline analysis.

JRMP framing, from `java.rmi.transport.TransportConstants`:
    magic "JRMI" | version(2) = 2 | protocol(1)
    protocol: 0x4b StreamProtocol, 0x4c SingleOpProtocol, 0x4d MultiplexProtocol
    server answers StreamProtocol with 0x4e ProtocolAck + UTF host + port(4),
    and the client answers that with its own endpoint (UTF host + port).
    messages: 0x50 Call, 0x51 Return, 0x52 Ping, 0x53 PingAck, 0x54 DGCAck
A JDK "UTF" string is u2 length + modified-UTF8 bytes.

Event fields avoid the keys `name`, `protocol`, `peer`, `port` and `transport`:
the JSONL sink already sets those on every record, so a handler field with one
of those keys is a duplicate-keyword TypeError at emit time. Hence
`jrmp_protocol=` / `protocol_name=` on rmi_connect.

`exploit_attempt` is emitted in the same shape as the capture pipeline's
(via `exploits.as_event_fields`) so one query finds every exploit event.
"""

from __future__ import annotations

import logging
import struct

from honeyknot.exploits import as_event_fields, synthetic_hit
from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.rmi")

MAGIC = b"JRMI"
HEADER_LEN = 7  # magic(4) + version(2) + protocol(1)

STREAM_PROTOCOL = 0x4B
SINGLE_OP_PROTOCOL = 0x4C
MULTIPLEX_PROTOCOL = 0x4D
PROTOCOL_ACK = 0x4E
PROTOCOL_NACK = 0x4F

PROTOCOL_NAMES = {
    STREAM_PROTOCOL: "StreamProtocol",
    SINGLE_OP_PROTOCOL: "SingleOpProtocol",
    MULTIPLEX_PROTOCOL: "MultiplexProtocol",
}

MSG_CALL = 0x50
MSG_RETURN = 0x51
MSG_PING = 0x52
MSG_PING_ACK = 0x53
MSG_DGC_ACK = 0x54

MESSAGE_NAMES = {
    MSG_CALL: "Call",
    MSG_RETURN: "Return",
    MSG_PING: "Ping",
    MSG_PING_ACK: "PingAck",
    MSG_DGC_ACK: "DgcAck",
}

# Java serialization stream header: STREAM_MAGIC 0xaced + STREAM_VERSION 5.
SER_MAGIC = b"\xac\xed\x00\x05"

MAX_BUFFER = 1 << 20  # 1 MiB of unparsed stream is plenty for any gadget chain
SCAN_WINDOW = 4096
MIN_RUN = 5
MAX_RUNS = 20
MAX_RUN_LEN = 120

# Substrings that only show up in a serialized stream when someone is trying
# something. Matched case-insensitively against the scraped runs.
GADGET_MARKERS = (
    "InvokerTransformer",
    "AnnotationInvocationHandler",
    "TemplatesImpl",
    "ChainedTransformer",
    "jndi:",
    "ldap://",
    "rmi://",
)


class RMIHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        # The client opens with the JRMI header; we say nothing first.
        ctx.state["buffer"] = bytearray()
        ctx.state["handshake_done"] = False
        ctx.state["endpoint_pending"] = False
        ctx.state["call_open"] = False

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)
        if len(buf) > MAX_BUFFER:
            ctx.request_logger.info("%s: rmi buffer cap hit (%d bytes) — dropping",
                                    ctx.addr, len(buf))
            ctx.close()
            return

        if not ctx.state.get("handshake_done"):
            if len(buf) < HEADER_LEN:
                return  # header split across reads, or a silent client
            if bytes(buf[:4]) != MAGIC:
                ctx.request_logger.info("%s: rmi bad magic %s (%d bytes)",
                                        ctx.addr, bytes(buf[:8]).hex(), len(buf))
                ctx.close()
                return
            version, proto = struct.unpack(">HB", buf[4:HEADER_LEN])
            del buf[:HEADER_LEN]
            ctx.state["handshake_done"] = True
            await self._ack(version, proto, ctx)

        while buf and not ctx.closed:
            if (ctx.state.get("endpoint_pending")
                    and not self._consume_endpoint(buf, ctx)):
                return  # need more bytes to finish the endpoint identifier
            if not buf:
                return
            await self._handle_message(buf, ctx)

    async def _ack(self, version: int, proto: int, ctx: ConnectionContext) -> None:
        name = PROTOCOL_NAMES.get(proto, "unknown")
        ctx.request_logger.info("%s: rmi handshake version=%d protocol=0x%02x (%s)",
                                ctx.addr, version, proto, name)
        ctx.event("rmi_connect", jrmp_protocol=f"0x{proto:02x}",
                  protocol_name=name, version=version)

        if proto in (STREAM_PROTOCOL, MULTIPLEX_PROTOCOL):
            # ProtocolAck carries the server's view of the client endpoint.
            # Real registries echo the peer address; port 0 is what the JDK
            # itself sends when it has no better answer.
            host = ctx.addr[0] if ctx.addr else "0.0.0.0"
            await ctx.send(bytes([PROTOCOL_ACK]) + _utf(host) + struct.pack(">I", 0))
            ctx.state["endpoint_pending"] = True
        elif proto == SINGLE_OP_PROTOCOL:
            # SingleOpProtocol gets no ack at all — the client just sends its
            # one message and we read it.
            ctx.state["endpoint_pending"] = False
        else:
            await ctx.send(bytes([PROTOCOL_NACK]))
            ctx.close()

    def _consume_endpoint(self, buf: bytearray, ctx: ConnectionContext) -> bool:
        """Eat the client's endpoint identifier (UTF host + port) after our ack.

        Returns True when we're done with it (consumed, or decided it isn't
        there), False when we need more bytes. Some tools skip the endpoint and
        go straight to a message, so a known message-type byte clears the flag.
        """
        if buf[0] in MESSAGE_NAMES:
            ctx.state["endpoint_pending"] = False
            return True
        if len(buf) < 2:
            return False
        length = struct.unpack(">H", buf[:2])[0]
        if length > 255:  # not a hostname — treat as message data
            ctx.state["endpoint_pending"] = False
            return True
        if len(buf) < 2 + length + 4:
            return False
        host = bytes(buf[2:2 + length]).decode("utf-8", errors="replace")
        port = struct.unpack(">I", buf[2 + length:6 + length])[0]
        del buf[:6 + length]
        ctx.state["endpoint_pending"] = False
        ctx.request_logger.info("%s: rmi client endpoint %s:%d", ctx.addr, host, port)
        return True

    async def _handle_message(self, buf: bytearray, ctx: ConnectionContext) -> None:
        mtype = buf[0]
        if mtype not in MESSAGE_NAMES:
            # Either a continuation of the Call body we already consumed (a
            # serialized stream has no length prefix, so we can't frame it) or
            # junk. Either way: scan it, drain it, stay open.
            body = bytes(buf)
            buf.clear()
            if ctx.state.get("call_open"):
                _scan_serialized(body, ctx)
            else:
                ctx.request_logger.info("%s: rmi unframed %d bytes (head=%s)",
                                        ctx.addr, len(body), body[:16].hex())
                _scan_serialized(body, ctx)
            return

        name = MESSAGE_NAMES[mtype]
        if mtype == MSG_CALL:
            # A Call is a serialized stream with no length field, so everything
            # buffered belongs to it.
            body = bytes(buf[1:])
            buf.clear()
            ctx.state["call_open"] = True
            ctx.request_logger.info("%s: rmi Call %d bytes (head=%s)",
                                    ctx.addr, len(body), body[:16].hex())
            ctx.event("rmi_message", type=f"0x{mtype:02x}", type_name=name,
                      bytes=len(body))
            _scan_serialized(body, ctx)
            # Reply: message type 0x51 (Return, per TransportConstants) followed
            # by a bare serialization stream header and nothing else. We do not
            # attempt a real ReturnValue — we never deserialized the argument,
            # so we have nothing to return, and a truncated stream leaves the
            # client blocked in readObject instead of erroring out, which keeps
            # the socket open for whatever it sends next.
            await ctx.send(bytes([MSG_RETURN]) + SER_MAGIC)
            return

        del buf[:1]
        ctx.request_logger.info("%s: rmi %s (0x%02x)", ctx.addr, name, mtype)
        ctx.event("rmi_message", type=f"0x{mtype:02x}", type_name=name, bytes=0)
        if mtype == MSG_PING:
            await ctx.send(bytes([MSG_PING_ACK]))
        elif mtype == MSG_DGC_ACK:
            # DGCAck trails a 14-byte UniqueIdentifier; drop it if it's here.
            del buf[:14]


def _scan_serialized(body: bytes, ctx: ConnectionContext) -> None:
    """Find the Java serialization header and mine the payload for class names."""
    offset = body.find(SER_MAGIC)
    if offset < 0:
        return
    strings = _ascii_runs(body[offset:offset + SCAN_WINDOW])
    ctx.request_logger.info("%s: rmi java serialized stream at offset %d, %d strings",
                            ctx.addr, offset, len(strings))
    ctx.event("java_serialized", offset=offset, strings=strings)

    haystack = "\n".join(strings).lower()
    indicators = [m for m in GADGET_MARKERS if m.lower() in haystack]
    if indicators:
        ctx.request_logger.info("%s: rmi gadget markers %r", ctx.addr, indicators)
        ctx.event("exploit_attempt", indicators=indicators,
                  **as_event_fields([synthetic_hit(
                      id="java-deserialization",
                      title="JRMP serialized gadget chain",
                      category="deserialization", severity="critical",
                      match=", ".join(indicators)[:160])]))


def _ascii_runs(data: bytes, min_len: int = MIN_RUN,
                max_runs: int = MAX_RUNS, max_len: int = MAX_RUN_LEN) -> list[str]:
    """Every printable-ASCII run of `min_len`+ chars, capped for log sanity."""
    runs: list[str] = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
            continue
        if len(current) >= min_len:
            runs.append(current[:max_len].decode("ascii", errors="replace"))
            if len(runs) >= max_runs:
                return runs
        current.clear()
    if len(current) >= min_len and len(runs) < max_runs:
        runs.append(current[:max_len].decode("ascii", errors="replace"))
    return runs


def _utf(value: str) -> bytes:
    """JDK modified-UTF8 string: u2 length + bytes."""
    raw = value.encode("utf-8", errors="replace")[:0xFFFF]
    return struct.pack(">H", len(raw)) + raw
