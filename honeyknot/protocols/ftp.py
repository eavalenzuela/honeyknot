"""FTP honeypot: USER/PASS → plausible command acks, log what they try.

No actual data channel is offered — we refuse PORT/PASV so attackers reveal
what they were going to upload via `STOR`/`APPE` command lines. The goal is
credential capture and command capture, not file transfer.
"""

import logging

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.ftp")

DEFAULT_BANNER = "vsFTPd 3.0.3"


class FTPHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        banner = self.config.protocol_opts.get("banner", DEFAULT_BANNER)
        ctx.state["buffer"] = b""
        ctx.state["user"] = None
        await ctx.send(f"220 (ready) {banner}\r\n".encode())

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.request_logger.info("%s: %s", ctx.addr, data)
        ctx.state["buffer"] += data
        while b"\r\n" in ctx.state["buffer"]:
            line, ctx.state["buffer"] = ctx.state["buffer"].split(b"\r\n", 1)
            await self._handle_command(line, ctx)
            if ctx.closed:
                break

    async def _handle_command(self, line: bytes, ctx: ConnectionContext) -> None:
        try:
            text = line.decode("ascii", errors="replace").strip()
        except Exception:
            await ctx.send(b"500 Syntax error\r\n")
            return

        if not text:
            return

        parts = text.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "USER":
            ctx.state["user"] = arg
            await ctx.send(b"331 Please specify the password.\r\n")
        elif cmd == "PASS":
            logger.info("FTP creds from %s: user=%r pass=%r",
                        ctx.addr, ctx.state.get("user"), arg)
            ctx.event("credentials",
                      service="ftp",
                      username=ctx.state.get("user"),
                      password=arg)
            await ctx.send(b"230 Login successful.\r\n")
        elif cmd == "SYST":
            await ctx.send(b"215 UNIX Type: L8\r\n")
        elif cmd == "FEAT":
            await ctx.send(b"211-Features:\r\n EPSV\r\n PASV\r\n SIZE\r\n211 End\r\n")
        elif cmd in ("PWD", "XPWD"):
            await ctx.send(b'257 "/" is the current directory\r\n')
        elif cmd == "TYPE":
            await ctx.send(b"200 Switching type.\r\n")
        elif cmd == "CWD":
            await ctx.send(b"250 Directory successfully changed.\r\n")
        elif cmd in ("PASV", "EPSV", "PORT", "EPRT"):
            # Refuse data channel — we want them to keep issuing commands.
            await ctx.send(b"425 Cannot open data connection.\r\n")
        elif cmd in ("LIST", "NLST", "STOR", "APPE", "RETR", "DELE"):
            logger.info("FTP %s from %s: %s", cmd, ctx.addr, arg)
            ctx.event("command", service="ftp", command=cmd, arg=arg)
            await ctx.send(b"425 Use PORT or PASV first.\r\n")
        elif cmd == "QUIT":
            await ctx.send(b"221 Goodbye.\r\n")
            ctx.close()
        else:
            await ctx.send(b"500 Unknown command.\r\n")
