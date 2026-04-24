"""SNMP honeypot: log community string attempts on UDP/161.

SNMP is ASN.1 BER encoded. Parsing it properly is a project; here we do
the minimum needed to extract the community string (the only credential in
SNMPv1/v2c) and log it. We don't reply — real targets silently drop on bad
community strings, so attackers moving on without a reply is realistic
behavior. If the reply is needed later we can extend.
"""

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.snmp")


class SNMPHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        community = _extract_community(data)
        if community is not None:
            logger.info("SNMP probe from %s: community=%r len=%d",
                        ctx.addr, community, len(data))
        else:
            logger.info("SNMP probe from %s: (unparseable) len=%d",
                        ctx.addr, len(data))


def _extract_community(data: bytes) -> str | None:
    """Walk a BER SEQUENCE { version INTEGER, community OCTET STRING, ... }."""
    pos = 0
    try:
        if pos >= len(data) or data[pos] != 0x30:
            return None
        pos += 1
        pos = _skip_length(data, pos)
        # INTEGER (version)
        if pos >= len(data) or data[pos] != 0x02:
            return None
        pos += 1
        vlen, pos = _read_length(data, pos)
        pos += vlen
        # OCTET STRING (community)
        if pos >= len(data) or data[pos] != 0x04:
            return None
        pos += 1
        clen, pos = _read_length(data, pos)
        if pos + clen > len(data):
            return None
        return data[pos:pos + clen].decode("ascii", errors="replace")
    except (IndexError, ValueError):
        return None


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first & 0x80 == 0:
        return first, pos
    num = first & 0x7F
    if num == 0 or num > 4:
        raise ValueError("bad length")
    length = int.from_bytes(data[pos:pos + num], "big")
    return length, pos + num


def _skip_length(data: bytes, pos: int) -> int:
    _, pos = _read_length(data, pos)
    return pos
