"""Postgres honeypot on TCP/5432 — handshake + cleartext password capture.

Client-speaks-first. The first message is one of:
  SSLRequest (8 bytes, special int32 0x04D2162F) — we reply 'N' = no SSL
    and expect a StartupMessage on the same connection.
  StartupMessage: 4-byte total length + 4-byte protocol version (major 3)
    + key/value pairs terminated by NUL.

We pull user/database/application_name, send AuthenticationCleartextPassword
(R0 then auth type 3), read the client PasswordMessage, log it, then
respond with ErrorResponse "password authentication failed" and drop.
"""

from __future__ import annotations

import logging
import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.postgres")

SSL_REQUEST = 0x04D2162F
STARTUP_PROTO_V3 = 0x00030000  # major=3 minor=0


class PostgresHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state.setdefault("buffer", bytearray())
        ctx.state.setdefault("phase", "startup")
        ctx.state["buffer"].extend(data)

        while not ctx.closed:
            phase = ctx.state["phase"]
            if phase == "startup":
                if not await self._handle_startup(ctx):
                    return
            elif phase == "password":
                if not await self._handle_password(ctx):
                    return
            else:
                return

    async def _handle_startup(self, ctx: ConnectionContext) -> bool:
        buf = ctx.state["buffer"]
        if len(buf) < 8:
            return False
        length = int.from_bytes(buf[:4], "big")
        if length < 8 or length > 65536:
            ctx.close()
            return False
        if len(buf) < length:
            return False
        protocol = int.from_bytes(buf[4:8], "big")
        if protocol == SSL_REQUEST:
            ctx.state["buffer"] = buf[length:]
            await ctx.send(b"N")
            return True  # loop to expect a real StartupMessage next

        # StartupMessage
        body = bytes(buf[8:length])
        ctx.state["buffer"] = buf[length:]
        params = _parse_params(body)
        user = params.get("user", "")
        database = params.get("database", user)
        app = params.get("application_name", "")
        logger.info("Postgres startup from %s: user=%r db=%r app=%r",
                    ctx.addr, user, database, app)
        ctx.state["startup_params"] = params
        # AuthenticationCleartextPassword: 'R' + len=8 + type=3
        await ctx.send(b"R" + struct.pack(">II", 8, 3))
        ctx.state["phase"] = "password"
        return True

    async def _handle_password(self, ctx: ConnectionContext) -> bool:
        buf = ctx.state["buffer"]
        if len(buf) < 5:
            return False
        msg_type = buf[0:1]
        length = int.from_bytes(buf[1:5], "big")
        if length < 4 or length > 10000:
            ctx.close()
            return False
        if len(buf) < 1 + length:
            return False
        body = bytes(buf[5:1 + length])
        ctx.state["buffer"] = buf[1 + length:]

        if msg_type != b"p":
            ctx.close()
            return False
        password = body.rstrip(b"\x00").decode("utf-8", errors="replace")
        params = ctx.state.get("startup_params", {})
        logger.info("Postgres creds from %s: user=%r pass=%r",
                    ctx.addr, params.get("user"), password)
        ctx.event("credentials",
                  service="postgres",
                  username=params.get("user") or "",
                  password=password,
                  database=params.get("database") or "")

        await ctx.send(_error_response(
            severity="FATAL",
            code="28P01",
            message="password authentication failed",
        ))
        ctx.close()
        return False


def _parse_params(body: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    parts = body.split(b"\x00")
    # Skip trailing empty strings and odd element counts
    for i in range(0, len(parts) - 1, 2):
        name = parts[i]
        if not name:
            break
        value = parts[i + 1]
        out[name.decode("utf-8", errors="replace")] = \
            value.decode("utf-8", errors="replace")
    return out


def _error_response(*, severity: str, code: str, message: str) -> bytes:
    body = b"".join([
        b"S" + severity.encode("ascii") + b"\x00",
        b"V" + severity.encode("ascii") + b"\x00",
        b"C" + code.encode("ascii") + b"\x00",
        b"M" + message.encode("utf-8") + b"\x00",
        b"\x00",  # terminator
    ])
    return b"E" + struct.pack(">I", 4 + len(body)) + body
