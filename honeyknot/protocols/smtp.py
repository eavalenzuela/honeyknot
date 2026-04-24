"""SMTP honeypot: walk a client through HELO/EHLO → MAIL → RCPT → DATA → body.

The goal is to get to DATA so we capture the full message body in the raw
sink. We ack everything plausibly, refuse nothing, and stay in DATA until
the client sends the `<CRLF>.<CRLF>` terminator.
"""

import logging

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.smtp")

DEFAULT_HOSTNAME = "mail.local"
DATA_TERMINATOR = b"\r\n.\r\n"


class SMTPHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        hostname = self.config.protocol_opts.get("hostname", DEFAULT_HOSTNAME)
        ctx.state["hostname"] = hostname
        ctx.state["buffer"] = b""
        ctx.state["in_data"] = False
        await ctx.send(f"220 {hostname} ESMTP Postfix\r\n".encode())

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.request_logger.info("%s: %s", ctx.addr, data)
        ctx.state["buffer"] += data

        if ctx.state["in_data"]:
            if DATA_TERMINATOR in ctx.state["buffer"]:
                ctx.state["in_data"] = False
                ctx.state["buffer"] = b""
                await ctx.send(b"250 2.0.0 Ok: queued as 1A2B3C4D5E\r\n")
            return

        # Process complete command lines
        while b"\r\n" in ctx.state["buffer"]:
            line, ctx.state["buffer"] = ctx.state["buffer"].split(b"\r\n", 1)
            await self._handle_command(line, ctx)
            if ctx.closed or ctx.state["in_data"]:
                break

    async def _handle_command(self, line: bytes, ctx: ConnectionContext) -> None:
        try:
            text = line.decode("ascii", errors="replace")
        except Exception:
            await ctx.send(b"500 5.5.2 Syntax error\r\n")
            return

        cmd = text.split(" ", 1)[0].upper()
        hostname = ctx.state["hostname"]

        if cmd == "EHLO":
            await ctx.send(
                f"250-{hostname}\r\n"
                f"250-PIPELINING\r\n"
                f"250-SIZE 10485760\r\n"
                f"250-8BITMIME\r\n"
                f"250 HELP\r\n".encode()
            )
        elif cmd == "HELO":
            await ctx.send(f"250 {hostname}\r\n".encode())
        elif cmd in ("MAIL", "RCPT"):
            await ctx.send(b"250 2.1.0 Ok\r\n")
        elif cmd == "DATA":
            ctx.state["in_data"] = True
            await ctx.send(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        elif cmd in ("RSET", "NOOP"):
            await ctx.send(b"250 2.0.0 Ok\r\n")
        elif cmd == "QUIT":
            await ctx.send(f"221 2.0.0 {hostname} closing connection\r\n".encode())
            ctx.close()
        elif cmd == "AUTH":
            # Invite a cred dump. Accept any credentials.
            await ctx.send(b"334 VXNlcm5hbWU6\r\n")
            ctx.state["auth_pending"] = True
        else:
            if ctx.state.pop("auth_pending", False):
                await ctx.send(b"235 2.7.0 Authentication successful\r\n")
            else:
                await ctx.send(b"250 2.0.0 Ok\r\n")
