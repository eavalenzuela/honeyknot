"""MQTT honeypot on TCP/1883 — captures client_id + credentials.

Parses MQTT 3.1 / 3.1.1 / 5.0 CONNECT packets enough to pull client
identifier, username, password. Responds with CONNACK success so the
client proceeds to PUBLISH/SUBSCRIBE, which we log without acting on.
Handles PINGREQ so the connection survives long enough to collect
follow-up traffic.

Wire format:
    Fixed header: type(4) + flags(4) byte + remaining length (varint)
    CONNECT payload: protocol name, level, flags, keepalive, then
    UTF-8 strings (length-prefixed u16): client_id, [will topic], [will msg],
    [username], [password].
"""

from __future__ import annotations

import logging

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.mqtt")

PKT_CONNECT = 1
PKT_CONNACK = 2
PKT_PUBLISH = 3
PKT_SUBSCRIBE = 8
PKT_SUBACK = 9
PKT_PINGREQ = 12
PKT_PINGRESP = 13
PKT_DISCONNECT = 14


class MQTTHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state.setdefault("buffer", bytearray())
        ctx.state["buffer"].extend(data)

        while not ctx.closed:
            parsed = _parse_packet(ctx.state["buffer"])
            if parsed is None:
                return  # need more bytes
            if parsed == "bad":
                ctx.close()
                return
            pkt_type, flags, payload, consumed = parsed
            ctx.state["buffer"] = ctx.state["buffer"][consumed:]
            await self._handle(pkt_type, flags, payload, ctx)

    async def _handle(self, pkt_type: int, flags: int, payload: bytes,
                      ctx: ConnectionContext) -> None:
        if pkt_type == PKT_CONNECT:
            info = _parse_connect(payload)
            if info is None:
                ctx.close()
                return
            logger.info("MQTT CONNECT from %s: client_id=%r user=%r pass=%r",
                        ctx.addr, info["client_id"],
                        info.get("username"), info.get("password"))
            ctx.event("credentials",
                      service="mqtt",
                      client_id=info["client_id"],
                      username=info.get("username") or "",
                      password=info.get("password") or "")
            # CONNACK: session present=0, return code=0 (accepted)
            await ctx.send(bytes([PKT_CONNACK << 4, 2, 0x00, 0x00]))
        elif pkt_type == PKT_PINGREQ:
            await ctx.send(bytes([PKT_PINGRESP << 4, 0]))
        elif pkt_type == PKT_PUBLISH:
            qos = (flags >> 1) & 0x03
            if len(payload) < 2:
                return
            topic_len = int.from_bytes(payload[:2], "big")
            if 2 + topic_len > len(payload):
                return
            topic = payload[2:2 + topic_len].decode("utf-8", errors="replace")
            pos = 2 + topic_len
            packet_id = None
            if qos > 0 and pos + 2 <= len(payload):
                packet_id = int.from_bytes(payload[pos:pos + 2], "big")
                pos += 2
            body = payload[pos:]
            logger.info("MQTT PUBLISH from %s: topic=%r body=%d bytes "
                        "qos=%d", ctx.addr, topic, len(body), qos)
            ctx.event("mqtt_publish",
                      topic=topic, qos=qos, packet_id=packet_id,
                      body_bytes=len(body), body=body)
            if qos == 1 and packet_id is not None:
                # PUBACK: type=4 (<<4), remaining=2, packet_id
                await ctx.send(bytes([0x40, 0x02])
                               + packet_id.to_bytes(2, "big"))
            elif qos == 2 and packet_id is not None:
                # PUBREC: type=5 (<<4), remaining=2, packet_id
                await ctx.send(bytes([0x50, 0x02])
                               + packet_id.to_bytes(2, "big"))
        elif pkt_type == PKT_SUBSCRIBE:
            # Reply SUBACK accepting all topic filters at QoS 0.
            if len(payload) < 2:
                return
            msg_id = payload[:2]
            # Count topic filters quickly
            pos = 2
            topics = 0
            while pos + 2 <= len(payload):
                tl = int.from_bytes(payload[pos:pos + 2], "big")
                pos += 2 + tl + 1  # +1 for QoS byte
                topics += 1
                if pos > len(payload):
                    break
            body = msg_id + b"\x00" * max(1, topics)
            remaining = _encode_varint(len(body))
            await ctx.send(bytes([PKT_SUBACK << 4]) + remaining + body)
            logger.info("MQTT SUBSCRIBE from %s: %d filter(s)",
                        ctx.addr, topics)
        elif pkt_type == PKT_DISCONNECT:
            ctx.close()


def _parse_packet(buf: bytearray):
    if len(buf) < 2:
        return None
    b0 = buf[0]
    pkt_type = (b0 >> 4) & 0x0F
    flags = b0 & 0x0F
    # Decode remaining length varint (1-4 bytes)
    multiplier = 1
    value = 0
    pos = 1
    while True:
        if pos > 4:
            return "bad"
        if pos >= len(buf):
            return None
        byte = buf[pos]
        value += (byte & 0x7F) * multiplier
        pos += 1
        if not (byte & 0x80):
            break
        multiplier *= 128
    if pos + value > len(buf):
        return None
    payload = bytes(buf[pos:pos + value])
    return pkt_type, flags, payload, pos + value


def _encode_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _parse_connect(payload: bytes) -> dict | None:
    """Extract client_id / username / password from a CONNECT payload."""
    pos = 0
    name, pos = _utf8_str(payload, pos)
    if name is None:
        return None
    if pos >= len(payload):
        return None
    level = payload[pos]
    pos += 1
    if pos >= len(payload):
        return None
    flags = payload[pos]
    pos += 1
    if pos + 2 > len(payload):
        return None
    # skip keepalive
    pos += 2
    if level >= 5 and pos < len(payload):
        # MQTT 5 has a properties section: varint length + opaque bytes
        prop_len, pos = _varint(payload, pos)
        if prop_len is None:
            return None
        pos += prop_len

    client_id, pos = _utf8_str(payload, pos)
    if client_id is None:
        return None

    username = password = None
    # flags bits: UserName(7) Password(6) WillRetain(5) WillQoS(4-3)
    # Will(2) CleanSession(1) Reserved(0)
    has_will = bool(flags & 0x04)
    has_user = bool(flags & 0x80)
    has_pass = bool(flags & 0x40)

    if has_will:
        if level >= 5:
            will_prop_len, pos = _varint(payload, pos)
            if will_prop_len is None:
                return None
            pos += will_prop_len
        _, pos = _utf8_str(payload, pos)        # will topic
        if pos is None:
            return None
        # Will payload is binary (length-prefixed bytes), not a UTF-8 string.
        if pos + 2 > len(payload):
            return None
        wp_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + wp_len
    if has_user:
        username, pos = _utf8_str(payload, pos)
    if has_pass:
        # Password is actually binary-data in MQTT but practically UTF-8.
        password, pos = _utf8_str(payload, pos)

    return {
        "client_id": client_id,
        "username": username,
        "password": password,
    }


def _utf8_str(buf: bytes, pos: int):
    if pos + 2 > len(buf):
        return None, pos
    length = int.from_bytes(buf[pos:pos + 2], "big")
    pos += 2
    if pos + length > len(buf):
        return None, pos
    s = buf[pos:pos + length].decode("utf-8", errors="replace")
    return s, pos + length


def _varint(buf: bytes, pos: int):
    multiplier = 1
    value = 0
    i = 0
    while True:
        if i > 3 or pos + i >= len(buf):
            return None, pos
        byte = buf[pos + i]
        value += (byte & 0x7F) * multiplier
        if not (byte & 0x80):
            return value, pos + i + 1
        i += 1
        multiplier *= 128


