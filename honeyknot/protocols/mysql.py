"""MySQL honeypot on TCP/3306 — server-first greeting, captures Login.

Sends a 10-protocol handshake greeting on connect, parses the client's
HandshakeResponse, logs username + auth_response bytes, returns an
Access denied error packet and drops.

Packet format: 3-byte LE length + 1-byte sequence id + payload.
"""

from __future__ import annotations

import logging
import os
import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.mysql")

SERVER_VERSION = b"5.7.38-log\x00"
CAP_FLAGS_LOWER = 0xFFFF  # all typical caps
CAP_FLAGS_UPPER = 0x81FF  # plugin auth + secure conn + protocol41
CHARSET_UTF8 = 0x21
STATUS_AUTOCOMMIT = 0x0002


class MySQLHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] = bytearray()
        # 20-byte challenge split 8+12 by historical accident of the protocol.
        challenge = os.urandom(20)
        ctx.state["challenge"] = challenge

        payload = bytearray()
        payload.append(10)                                        # protocol version
        payload += SERVER_VERSION                                  # server version + NUL
        payload += struct.pack("<I", 1)                            # thread id
        payload += challenge[:8] + b"\x00"                         # auth plugin data part 1
        payload += struct.pack("<H", CAP_FLAGS_LOWER)              # caps low
        payload.append(CHARSET_UTF8)                               # charset
        payload += struct.pack("<H", STATUS_AUTOCOMMIT)            # status flags
        payload += struct.pack("<H", CAP_FLAGS_UPPER)              # caps high
        payload.append(len(challenge) + 1)                         # auth plugin data length
        payload += b"\x00" * 10                                    # reserved
        payload += challenge[8:] + b"\x00"                         # auth plugin data part 2
        payload += b"mysql_native_password\x00"

        await self._send_packet(ctx, 0, bytes(payload))

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state["buffer"].extend(data)
        pkt = _read_packet(ctx.state["buffer"])
        if pkt is None:
            return
        _seq, payload, consumed = pkt
        ctx.state["buffer"] = ctx.state["buffer"][consumed:]

        info = _parse_login(payload)
        if info is not None:
            logger.info("MySQL login from %s: user=%r db=%r auth_hex=%s",
                        ctx.addr, info["user"], info.get("database"),
                        info["auth"].hex())
            ctx.event("credentials",
                      service="mysql",
                      username=info["user"],
                      database=info.get("database") or "",
                      auth_response_hex=info["auth"].hex(),
                      challenge_hex=ctx.state["challenge"].hex())

        # Error packet: 0xFF + u16 error code 1045 (Access denied) + sql state + msg
        err = (b"\xff"
               + struct.pack("<H", 1045)
               + b"#28000"
               + b"Access denied for user")
        await self._send_packet(ctx, 2, err)
        ctx.close()

    async def _send_packet(self, ctx: ConnectionContext, seq: int,
                           payload: bytes) -> None:
        header = struct.pack("<I", len(payload))[:3] + bytes([seq])
        await ctx.send(header + payload)


def _read_packet(buf: bytearray):
    if len(buf) < 4:
        return None
    length = int.from_bytes(buf[:3], "little")
    seq = buf[3]
    if len(buf) < 4 + length:
        return None
    return seq, bytes(buf[4:4 + length]), 4 + length


def _parse_login(payload: bytes) -> dict | None:
    """Best-effort parse of HandshakeResponse41 / 320 to extract user + auth."""
    if len(payload) < 4:
        return None
    caps = int.from_bytes(payload[:4], "little")
    is_41 = bool(caps & 0x00000200)
    pos = 4
    if is_41:
        pos += 4  # max packet size
        pos += 1  # charset
        pos += 23  # reserved
    else:
        pos += 3  # max packet size on 320
    # Null-terminated username
    end = payload.find(b"\x00", pos)
    if end == -1:
        return None
    user = payload[pos:end].decode("utf-8", errors="replace")
    pos = end + 1
    # auth response: length-encoded if plugin-auth-length-encoded, else lenenc or NUL-term
    if is_41 and (caps & 0x00200000):  # CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        n, pos = _lenenc_int(payload, pos)
        if n is None or pos + n > len(payload):
            return {"user": user, "auth": b"", "database": None}
        auth = payload[pos:pos + n]
        pos += n
    elif is_41 and (caps & 0x00008000):  # CLIENT_SECURE_CONNECTION
        if pos >= len(payload):
            return {"user": user, "auth": b"", "database": None}
        n = payload[pos]
        pos += 1
        if pos + n > len(payload):
            return {"user": user, "auth": b"", "database": None}
        auth = payload[pos:pos + n]
        pos += n
    else:
        end = payload.find(b"\x00", pos)
        if end == -1:
            return {"user": user, "auth": b"", "database": None}
        auth = payload[pos:end]
        pos = end + 1

    database = None
    if is_41 and (caps & 0x00000008):  # CLIENT_CONNECT_WITH_DB
        end = payload.find(b"\x00", pos)
        if end != -1:
            database = payload[pos:end].decode("utf-8", errors="replace")
    return {"user": user, "auth": auth, "database": database}


def _lenenc_int(buf: bytes, pos: int):
    if pos >= len(buf):
        return None, pos
    b = buf[pos]
    if b < 0xFB:
        return b, pos + 1
    if b == 0xFC:
        if pos + 3 > len(buf):
            return None, pos
        return int.from_bytes(buf[pos + 1:pos + 3], "little"), pos + 3
    if b == 0xFD:
        if pos + 4 > len(buf):
            return None, pos
        return int.from_bytes(buf[pos + 1:pos + 4], "little"), pos + 4
    if b == 0xFE:
        if pos + 9 > len(buf):
            return None, pos
        return int.from_bytes(buf[pos + 1:pos + 9], "little"), pos + 9
    return None, pos
