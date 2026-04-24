"""SSH honeypot: banner exchange and capture of the client's first KEX packet.

Real SSH is a binary protocol after the banner. We send a plausible server
banner (RFC 4253 section 4.2), read the client banner, then read one binary
packet (the client's SSH_MSG_KEXINIT) so it lands in the raw capture.
After that we drop — attackers probing for weak creds or CVE-style pre-auth
exploits will have revealed what tooling they're using by then.
"""

import logging

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.ssh")

DEFAULT_BANNER = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"


class SSHHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        banner = self.config.protocol_opts.get("banner", DEFAULT_BANNER)
        await ctx.send(banner.encode("ascii", errors="replace") + b"\r\n")
        ctx.state["banner_sent"] = True
        ctx.state["client_banner"] = None

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.request_logger.info("%s: %s", ctx.addr, data)

        if ctx.state.get("client_banner") is None:
            # Client banner is a single CRLF-terminated line.
            line_end = data.find(b"\n")
            if line_end != -1:
                ctx.state["client_banner"] = data[:line_end].rstrip(b"\r")
                logger.info("SSH client banner from %s: %r",
                            ctx.addr, ctx.state["client_banner"])
                remainder = data[line_end + 1:]
                if remainder:
                    # Any trailing bytes are already captured to the raw sink;
                    # one KEXINIT is enough signal. Close.
                    ctx.close()
                return

        # After we've seen the banner, the next chunk is binary KEX. Capture
        # already handled it; close so we don't tie up the connection.
        ctx.close()
