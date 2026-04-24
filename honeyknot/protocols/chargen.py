"""Chargen honeypot on UDP/19: respond with a tiny fixed string.

Real chargen is heavily abused for UDP amplification. We refuse to amplify:
respond with a single short line regardless of request size. The point is
to show up as "chargen exists" in scanners so we collect source addresses
of amplification attack recon.
"""

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.chargen")


class ChargenHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        logger.info("Chargen probe from %s (%d bytes in)", ctx.addr, len(data))
        # 72-byte response: below typical request size, never amplifies.
        ctx.send(b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\n")
