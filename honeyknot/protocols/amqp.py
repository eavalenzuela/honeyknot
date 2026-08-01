"""AMQP 0-9-1 honeypot on TCP/5672 — RabbitMQ mimic, captures SASL creds.

RabbitMQ on 5672 is brute-forced around the clock (the guest/guest
default is a standing joke), and a compromised broker is a durable
foothold for command distribution. AMQP 0-9-1 hands us plaintext SASL
credentials in the second frame of the connection — exactly what this
project exists to collect. We speak just enough of the protocol to greet,
accept whatever credentials arrive (acceptance makes tooling proceed to
Open and start declaring queues, which is far more telling than a
rejection), and log every method the client tries.

Wire format, all big-endian: 8-byte protocol header `AMQP\\x00\\x00\\x09\\x01`,
then frames of `type:u1 channel:u2 size:u4 payload frame_end:u1(0xCE)`.
A METHOD payload is `class_id:u2 method_id:u2 args`.
"""

from __future__ import annotations

import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

PROTO_HEADER = b"AMQP\x00\x00\x09\x01"

FRAME_METHOD = 1
FRAME_HEADER = 2
FRAME_BODY = 3
FRAME_HEARTBEAT = 8
FRAME_END = 0xCE
HEARTBEAT_FRAME = bytes([FRAME_HEARTBEAT, 0, 0, 0, 0, 0, 0, FRAME_END])
MAX_FRAME_SIZE = 1 << 20  # 1 MiB — nothing legitimate is bigger pre-Tune

CONNECTION = 10
CHANNEL = 20

METHOD_NAMES = {
    (10, 10): "Connection.Start", (10, 11): "Connection.StartOk",
    (10, 20): "Connection.Secure", (10, 21): "Connection.SecureOk",
    (10, 30): "Connection.Tune", (10, 31): "Connection.TuneOk",
    (10, 40): "Connection.Open", (10, 41): "Connection.OpenOk",
    (10, 50): "Connection.Close", (10, 51): "Connection.CloseOk",
    (20, 10): "Channel.Open", (20, 11): "Channel.OpenOk",
    (20, 40): "Channel.Close", (20, 41): "Channel.CloseOk",
    (40, 10): "Exchange.Declare", (40, 20): "Exchange.Delete",
    (50, 10): "Queue.Declare", (50, 20): "Queue.Bind",
    (50, 40): "Queue.Delete",
    (60, 20): "Basic.Consume", (60, 40): "Basic.Publish",
    (60, 70): "Basic.Get",
}


class AMQPHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] = bytearray()
        ctx.state["greeted"] = False

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)

        if not ctx.state.get("greeted"):
            if len(buf) < 8:
                return  # partial header — wait for more
            header = bytes(buf[:8])
            del buf[:8]
            if header != PROTO_HEADER:
                # Version negotiation failure: a real server answers with its
                # own header and closes. The offered header fingerprints the
                # client library (e.g. AMQP 1.0 vs 0-8 vs garbage).
                ctx.request_logger.info(
                    "%s: amqp unsupported protocol header %s — sent ours, closing",
                    ctx.addr, header.hex())
                ctx.event("amqp_bad_protocol_header", header_hex=header.hex())
                await ctx.send(PROTO_HEADER)
                ctx.close()
                return
            ctx.state["greeted"] = True
            ctx.request_logger.info("%s: amqp 0-9-1 header, sending Connection.Start",
                                    ctx.addr)
            await self._send_start(ctx)

        while not ctx.closed:
            if len(buf) < 7:
                return
            ftype, channel, size = struct.unpack(">BHI", buf[:7])
            if size > MAX_FRAME_SIZE:
                ctx.request_logger.info(
                    "%s: amqp frame size %d exceeds cap — closing", ctx.addr, size)
                ctx.close()
                return
            if len(buf) < 8 + size:
                return  # frame split across reads — wait for the rest
            if buf[7 + size] != FRAME_END:
                ctx.request_logger.info(
                    "%s: amqp framing error (end byte 0x%02x) — closing",
                    ctx.addr, buf[7 + size])
                ctx.close()
                return
            payload = bytes(buf[7:7 + size])
            del buf[:8 + size]
            await self._handle_frame(ftype, channel, payload, ctx)

    async def _handle_frame(self, ftype: int, channel: int, payload: bytes,
                            ctx: ConnectionContext) -> None:
        ctx.request_logger.info(
            "%s: amqp frame type=%d chan=%d size=%d head=%s",
            ctx.addr, ftype, channel, len(payload), payload[:16].hex())

        if ftype == FRAME_HEARTBEAT:
            await ctx.send(HEARTBEAT_FRAME)
            return
        if ftype != FRAME_METHOD or len(payload) < 4:
            # HEADER/BODY frames (publish content) are already raw-captured by
            # the server; nothing to answer.
            return

        class_id, method_id = struct.unpack(">HH", payload[:4])
        args = payload[4:]

        if (class_id, method_id) == (CONNECTION, 11):     # Connection.StartOk
            await self._handle_start_ok(args, ctx)
        elif (class_id, method_id) == (CONNECTION, 31):   # Connection.TuneOk
            pass                                          # no reply expected
        elif (class_id, method_id) == (CONNECTION, 40):   # Connection.Open
            vhost, _ = _parse_shortstr(args, 0)
            ctx.event("amqp_open", vhost=vhost)
            await self._send_method(ctx, 0, CONNECTION, 41, b"\x00")  # OpenOk
        elif (class_id, method_id) == (CONNECTION, 50):   # Connection.Close
            await self._send_method(ctx, 0, CONNECTION, 51, b"")      # CloseOk
            ctx.close()
        elif (class_id, method_id) == (CONNECTION, 51):   # client CloseOk
            ctx.close()
        elif (class_id, method_id) == (CHANNEL, 10):      # Channel.Open
            ctx.event("amqp_channel_open", channel=channel)
            await self._send_method(ctx, channel, CHANNEL, 11,
                                    b"\x00\x00\x00\x00")  # OpenOk(longstr "")
        elif (class_id, method_id) == (CHANNEL, 40):      # Channel.Close
            self._log_method(class_id, method_id, channel, payload, ctx)
            await self._send_method(ctx, channel, CHANNEL, 41, b"")   # CloseOk
        else:
            # Everything else (Queue.Declare, Basic.Publish, ...) is logged
            # only: the sync replies carry method-specific argument shapes
            # (generated names, message counts) and a wrong shape desyncs the
            # client worse than silence, which reads as a slow broker.
            self._log_method(class_id, method_id, channel, payload, ctx)

    def _log_method(self, class_id: int, method_id: int, channel: int,
                    payload: bytes, ctx: ConnectionContext) -> None:
        # The field is `method`, not `name`: `name` is reserved by the event
        # plumbing (ctx.event / the sink both take a positional `name`).
        method = METHOD_NAMES.get((class_id, method_id),
                                  f"{class_id}.{method_id}")
        ctx.event("amqp_method", class_id=class_id, method_id=method_id,
                  method=method, channel=channel, bytes=len(payload))

    async def _handle_start_ok(self, args: bytes, ctx: ConnectionContext) -> None:
        props, pos = _parse_table(args, 0)
        mechanism, pos = _parse_shortstr(args, pos)
        response, pos = _parse_longstr(args, pos)
        locale, _ = _parse_shortstr(args, pos)

        ctx.event("amqp_client",
                  product=str(props.get("product", "")),
                  version=str(props.get("version", "")),
                  platform=str(props.get("platform", "")))

        username = password = ""
        if mechanism.upper() == "PLAIN" and response.count(b"\x00") >= 2:
            _, user, pw = response.split(b"\x00", 2)
            username = user.decode("utf-8", errors="replace")
            password = pw.decode("utf-8", errors="replace")
        elif mechanism.upper() == "AMQPLAIN":
            creds = _parse_amqplain(response)
            username = str(creds.get("LOGIN", ""))
            password = str(creds.get("PASSWORD", ""))

        ctx.request_logger.info(
            "%s: amqp StartOk mech=%s user=%r client=%s/%s locale=%s",
            ctx.addr, mechanism, username,
            props.get("product", ""), props.get("version", ""), locale)
        if username or password:
            ctx.event("credentials", service="amqp", username=username,
                      password=password, mechanism=mechanism.upper())

        # Accept whatever arrived: the client proceeds to Open and starts
        # declaring queues, which tells us far more than a login rejection.
        tune = struct.pack(">HIH", 2047, 131072, 60)
        await self._send_method(ctx, 0, CONNECTION, 30, tune)

    async def _send_start(self, ctx: ConnectionContext) -> None:
        product = str(self.config.protocol_opts.get("product", "RabbitMQ"))
        version = str(self.config.protocol_opts.get("version", "3.8.9"))
        server_props = _build_table({
            "product": product,
            "version": version,
            "platform": "Erlang/OTP 23.2.1",
            "copyright": "Copyright (c) 2007-2020 VMware, Inc. or its affiliates.",
            "information": "Licensed under the MPL 2.0",
        })
        args = (bytes([0, 9])                       # version major/minor
                + server_props
                + _longstr(b"PLAIN AMQPLAIN")       # mechanisms
                + _longstr(b"en_US"))               # locales
        await self._send_method(ctx, 0, CONNECTION, 10, args)

    async def _send_method(self, ctx: ConnectionContext, channel: int,
                           class_id: int, method_id: int, args: bytes) -> None:
        payload = struct.pack(">HH", class_id, method_id) + args
        frame = (struct.pack(">BHI", FRAME_METHOD, channel, len(payload))
                 + payload + bytes([FRAME_END]))
        await ctx.send(frame)


# ---------------- wire helpers (encode) ----------------

def _longstr(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _build_table(entries: dict[str, str]) -> bytes:
    """Field table with all-longstr ('S') values."""
    body = b""
    for key, value in entries.items():
        kb = key.encode("utf-8")
        body += bytes([len(kb)]) + kb + b"S" + _longstr(value.encode("utf-8"))
    return struct.pack(">I", len(body)) + body


# ---------------- wire helpers (decode, never raise) ----------------

def _parse_shortstr(data: bytes, pos: int) -> tuple[str, int]:
    if pos >= len(data):
        return "", pos
    n = data[pos]
    if pos + 1 + n > len(data):
        return "", len(data)
    return data[pos + 1:pos + 1 + n].decode("utf-8", errors="replace"), pos + 1 + n


def _parse_longstr(data: bytes, pos: int) -> tuple[bytes, int]:
    if pos + 4 > len(data):
        return b"", pos
    n = int.from_bytes(data[pos:pos + 4], "big")
    if pos + 4 + n > len(data):
        return b"", len(data)
    return data[pos + 4:pos + 4 + n], pos + 4 + n


def _parse_table(data: bytes, pos: int) -> tuple[dict, int]:
    """Field table with a leading u4 size. Returns ({}, pos) if truncated."""
    if pos + 4 > len(data):
        return {}, pos
    size = int.from_bytes(data[pos:pos + 4], "big")
    end = pos + 4 + size
    if end > len(data):
        return {}, pos
    return _parse_table_body(data, pos + 4, end), end


def _parse_table_body(data: bytes, pos: int, end: int) -> dict:
    """Concatenated field-table entries: name_len:u1 name type_char value."""
    out: dict = {}
    while pos < end:
        nlen = data[pos]
        pos += 1
        if pos + nlen + 1 > end:
            break
        name = data[pos:pos + nlen].decode("utf-8", errors="replace")
        pos += nlen
        tchar = data[pos:pos + 1]
        pos += 1
        value, new_pos = _parse_value(tchar, data, pos, end)
        if new_pos is None:
            break  # unknown value type — bail rather than misparse
        out[name] = value
        pos = new_pos
    return out


def _parse_value(tchar: bytes, data: bytes, pos: int, end: int):
    """Decode one field-table value. Returns (value, new_pos) or (None, None)."""
    if tchar in (b"S", b"x"):
        if pos + 4 > end:
            return None, None
        n = int.from_bytes(data[pos:pos + 4], "big")
        if pos + 4 + n > end:
            return None, None
        raw = data[pos + 4:pos + 4 + n]
        value = raw.decode("utf-8", errors="replace") if tchar == b"S" else raw
        return value, pos + 4 + n
    if tchar == b"t":
        if pos + 1 > end:
            return None, None
        return bool(data[pos]), pos + 1
    if tchar in (b"b", b"B"):
        if pos + 1 > end:
            return None, None
        return data[pos], pos + 1
    if tchar in (b"u", b"U"):
        if pos + 2 > end:
            return None, None
        return int.from_bytes(data[pos:pos + 2], "big", signed=True), pos + 2
    if tchar in (b"I", b"i", b"f"):
        if pos + 4 > end:
            return None, None
        return int.from_bytes(data[pos:pos + 4], "big", signed=True), pos + 4
    if tchar in (b"l", b"L", b"d", b"T"):
        if pos + 8 > end:
            return None, None
        return int.from_bytes(data[pos:pos + 8], "big", signed=True), pos + 8
    if tchar == b"D":  # decimal: scale u1 + value u4
        if pos + 5 > end:
            return None, None
        return data[pos:pos + 5].hex(), pos + 5
    if tchar == b"s":  # RabbitMQ dialect: short string
        if pos >= end or pos + 1 + data[pos] > end:
            return None, None
        n = data[pos]
        return data[pos + 1:pos + 1 + n].decode("utf-8", errors="replace"), pos + 1 + n
    if tchar in (b"F", b"A"):
        if pos + 4 > end:
            return None, None
        n = int.from_bytes(data[pos:pos + 4], "big")
        if pos + 4 + n > end:
            return None, None
        if tchar == b"F":
            return _parse_table_body(data, pos + 4, pos + 4 + n), pos + 4 + n
        return "<array>", pos + 4 + n
    if tchar == b"V":
        return None, pos
    return None, None


def _parse_amqplain(response: bytes) -> dict:
    """AMQPLAIN response: a field table carrying LOGIN and PASSWORD.

    The spec says the table body ships *without* a leading u4 size, but some
    clients include one anyway — try the sized form first, fall back to
    parsing the whole blob as a bare table body.
    """
    if len(response) >= 4:
        size = int.from_bytes(response[:4], "big")
        if size == len(response) - 4:
            table = _parse_table_body(response, 4, len(response))
            if "LOGIN" in table or "PASSWORD" in table:
                return table
    return _parse_table_body(response, 0, len(response))
