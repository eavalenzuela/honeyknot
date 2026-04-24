"""Telnet honeypot: IAC negotiation + fake login prompt for credential capture.

Mirai-class scanners will drop their payload commands (wget/tftp/busybox)
right after a `login`/`password` exchange, so we want to keep the connection
open past that point and log each command line.
"""

import logging

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.telnet")

IAC = 0xFF
DO = 0xFD
DONT = 0xFE
WILL = 0xFB
WONT = 0xFC
SB = 0xFA
SE = 0xF0


class TelnetHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        hostname = self.config.protocol_opts.get("hostname", "localhost")
        ctx.state["hostname"] = hostname
        ctx.state["phase"] = "user"
        ctx.state["line"] = bytearray()
        ctx.state["user"] = None
        # Minimal IAC negotiation: WILL ECHO, WILL SGA, DO NAWS
        await ctx.send(bytes([IAC, WILL, 0x01, IAC, WILL, 0x03, IAC, DO, 0x1F]))
        await ctx.send(f"\r\n{hostname} login: ".encode())

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.request_logger.info("%s: %s", ctx.addr, data)
        stripped = self._strip_iac(data)
        for byte in stripped:
            if byte in (0x0D, 0x0A):
                if ctx.state["line"]:
                    await self._handle_line(bytes(ctx.state["line"]), ctx)
                    ctx.state["line"] = bytearray()
                if ctx.closed:
                    return
            elif byte == 0x08 or byte == 0x7F:
                if ctx.state["line"]:
                    ctx.state["line"].pop()
            elif 0x20 <= byte < 0x7F:
                ctx.state["line"].append(byte)

    @staticmethod
    def _strip_iac(data: bytes) -> bytes:
        out = bytearray()
        i = 0
        while i < len(data):
            b = data[i]
            if b == IAC and i + 1 < len(data):
                nxt = data[i + 1]
                if nxt == SB:
                    # Skip to IAC SE
                    end = data.find(bytes([IAC, SE]), i + 2)
                    i = end + 2 if end != -1 else len(data)
                    continue
                if nxt in (DO, DONT, WILL, WONT):
                    i += 3
                    continue
                i += 2
                continue
            out.append(b)
            i += 1
        return bytes(out)

    async def _handle_line(self, line: bytes, ctx: ConnectionContext) -> None:
        text = line.decode("ascii", errors="replace").rstrip()
        phase = ctx.state["phase"]

        if phase == "user":
            ctx.state["user"] = text
            ctx.state["phase"] = "pass"
            await ctx.send(b"Password: ")
        elif phase == "pass":
            logger.info("Telnet creds from %s: user=%r pass=%r",
                        ctx.addr, ctx.state.get("user"), text)
            ctx.event("credentials", service="telnet",
                      username=ctx.state.get("user"), password=text)
            ctx.state["phase"] = "shell"
            await ctx.send(b"\r\n# ")
        else:
            logger.info("Telnet cmd from %s: %r", ctx.addr, text)
            ctx.event("shell_command", service="telnet", command=text)
            if text.lower() in ("exit", "quit", "logout"):
                ctx.close()
                return
            await ctx.send(b"\r\n# ")
