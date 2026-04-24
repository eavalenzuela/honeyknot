"""SSDP honeypot on UDP/1900: respond to M-SEARCH so scanners flag the host.

SSDP is plain text HTTP-over-UDP. We reply to M-SEARCH * so discovery
scanners (Shodan, masscan users with --udp-http) see a response and log
its provenance for us.
"""

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.ssdp")


class SSDPHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        try:
            text = data.decode("ascii", errors="replace")
        except Exception:
            return
        first_line = text.split("\r\n", 1)[0]
        logger.info("SSDP probe from %s: %r", ctx.addr, first_line)

        if not text.upper().startswith("M-SEARCH"):
            return

        usn = self.config.protocol_opts.get(
            "usn", "uuid:2fac1234-31f8-11b4-a222-08002b34c003::upnp:rootdevice",
        )
        server = self.config.protocol_opts.get(
            "server", "Linux/5.4 UPnP/1.1 MiniUPnPd/2.2.1",
        )
        location = self.config.protocol_opts.get(
            "location", "http://127.0.0.1:80/rootDesc.xml",
        )

        reply = (
            "HTTP/1.1 200 OK\r\n"
            "CACHE-CONTROL: max-age=120\r\n"
            f"LOCATION: {location}\r\n"
            f"SERVER: {server}\r\n"
            "ST: upnp:rootdevice\r\n"
            f"USN: {usn}\r\n"
            "\r\n"
        )
        ctx.send(reply.encode("ascii"))
