"""NetBIOS-NS honeypot on UDP/137: log NBSTAT/Name queries.

The payload we care about is the decoded NetBIOS name in the query — it
reveals what the scanner thought it was looking for. NetBIOS names are
encoded via first-level encoding (each nibble -> 'A' + nibble). We log
the decoded name and stay silent (no reply).
"""

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.netbios_ns")


class NetBIOSNSHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        name = _decode_first_name(data)
        logger.info("NetBIOS-NS query from %s: name=%r len=%d",
                    ctx.addr, name, len(data))


def _decode_first_name(data: bytes) -> str | None:
    """Decode the first NetBIOS name (16 bytes encoded as 32 chars) after header."""
    if len(data) < 12 + 1 + 32:
        return None
    pos = 12
    length = data[pos]
    if length != 32:
        return None
    encoded = data[pos + 1:pos + 1 + 32]
    try:
        out = bytearray()
        for i in range(0, 32, 2):
            hi = encoded[i] - ord("A")
            lo = encoded[i + 1] - ord("A")
            if not (0 <= hi < 16 and 0 <= lo < 16):
                return None
            out.append((hi << 4) | lo)
        return out.rstrip(b" \x00").decode("ascii", errors="replace")
    except Exception:
        return None
