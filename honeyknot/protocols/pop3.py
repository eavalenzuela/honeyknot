"""POP3 honeypot on TCP/110 — credential capture via USER/PASS or APOP.

Server greets with a timestamp banner that enables APOP (RFC 1939 §7).
USER accepts; PASS captures and returns -ERR. APOP captures the digest
plus the original challenge so operators can attempt offline recovery.
"""

from __future__ import annotations

import logging
import os
import socket

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.pop3")


class POP3Handler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] = bytearray()
        timestamp = f"<{os.urandom(8).hex()}.{os.getpid()}@{socket.gethostname()}>"
        ctx.state["apop_challenge"] = timestamp
        await ctx.send(f"+OK POP3 honeyknot ready {timestamp}\r\n".encode())

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state["buffer"].extend(data)
        while b"\r\n" in ctx.state["buffer"]:
            line, _, rest = ctx.state["buffer"].partition(b"\r\n")
            ctx.state["buffer"] = bytearray(rest)
            await self._handle(bytes(line), ctx)
            if ctx.closed:
                return

    async def _handle(self, line: bytes, ctx: ConnectionContext) -> None:
        text = line.decode("utf-8", errors="replace").strip()
        if not text:
            return
        parts = text.split(" ", 2)
        command = parts[0].upper()

        if command == "CAPA":
            await ctx.send(b"+OK Capability list follows\r\n")
            await ctx.send(b"USER\r\nUIDL\r\nTOP\r\nSASL PLAIN LOGIN\r\n.\r\n")
        elif command == "USER":
            ctx.state["user"] = parts[1] if len(parts) > 1 else ""
            await ctx.send(b"+OK User accepted, send PASS\r\n")
        elif command == "PASS":
            password = parts[1] if len(parts) > 1 else ""
            user = ctx.state.get("user", "")
            logger.info("POP3 creds from %s: user=%r pass=%r",
                        ctx.addr, user, password)
            ctx.event("credentials", service="pop3",
                      username=user, password=password)
            await ctx.send(b"-ERR [AUTH] Authentication failed\r\n")
            ctx.close()
        elif command == "APOP":
            user = parts[1] if len(parts) > 1 else ""
            digest = parts[2] if len(parts) > 2 else ""
            logger.info("POP3 APOP from %s: user=%r digest=%r challenge=%r",
                        ctx.addr, user, digest,
                        ctx.state.get("apop_challenge"))
            ctx.event("credentials", service="pop3", mechanism="APOP",
                      username=user, digest=digest,
                      challenge=ctx.state.get("apop_challenge", ""))
            await ctx.send(b"-ERR [AUTH] Authentication failed\r\n")
            ctx.close()
        elif command == "QUIT":
            await ctx.send(b"+OK Goodbye\r\n")
            ctx.close()
        elif command in ("STAT", "LIST", "UIDL", "RETR", "DELE", "TOP"):
            logger.info("POP3 %s from %s (unauthenticated): args=%r",
                        command, ctx.addr, parts[1:])
            ctx.event("pop3_post_auth_attempt",
                      command=command, args=" ".join(parts[1:]))
            await ctx.send(b"-ERR Not authenticated\r\n")
        elif command == "NOOP":
            await ctx.send(b"+OK\r\n")
        else:
            await ctx.send(b"-ERR Unknown command\r\n")
