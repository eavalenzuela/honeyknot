"""Memcached honeypot on UDP/11211: log probes, never reply.

Memcached UDP was behind the biggest DDoS amplifications on record. The
safest defense against being weaponized is to stay silent. We log what
probes arrive so we can study reflection-attack recon, but we never emit a
datagram.
"""

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.memcached")


class MemcachedHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        if len(data) < 8:
            return
        payload = data[8:]
        try:
            text = payload.decode("ascii", errors="replace").strip()
        except Exception:
            text = ""
        logger.info("Memcached probe from %s: %r (silent)", ctx.addr, text[:80])
