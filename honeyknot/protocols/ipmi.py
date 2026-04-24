"""IPMI honeypot on UDP/623 — respond to RMCP ASF Presence Ping.

IPMI scanners (Shodan, ipmiping) send an ASF-RMCP Presence Ping and flag
the host as "IPMI" when they get a Presence Pong back. Anything past that
is IPMI over RMCP+, which requires real BMC logic we don't have. We just
answer the ping so the host shows up as "IPMI-capable" for attacker
reconnaissance attribution.

Wire format (attacker → us, Presence Ping, 16 bytes):
    RMCP header (4 bytes):  06 00 FF 06
    ASF header (4 bytes):   00 00 11 BE            (IANA enterprise)
    Message Type (1):       0x80 (Presence Ping)
    Message Tag (1):        <echo>
    Reserved (1):           0x00
    Data Length (1):        0x00

Pong (we send back, 28 bytes):
    RMCP header:            06 00 FF 06
    ASF header:             00 00 11 BE
    Message Type:           0x40 (Presence Pong)
    Message Tag:            <echo>
    Reserved:               0x00
    Data Length:            0x10 (16 bytes)
    IANA Enterprise:        00 00 11 BE
    OEM-defined:            00 00 00 00
    Supported Entities:     0x81 (IPMI supported)
    Supported Interactions: 0x00
    Reserved:               00 00 00 00 00 00
"""

from __future__ import annotations

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.ipmi")


class IPMIHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        if len(data) < 12:
            return
        # Only respond to RMCP ASF Presence Ping
        if data[:8] != b"\x06\x00\xff\x06\x00\x00\x11\xbe":
            logger.info("IPMI probe (not a ping) from %s: %d bytes",
                        ctx.addr, len(data))
            return
        msg_type = data[8]
        msg_tag = data[9]
        if msg_type != 0x80:
            logger.info("IPMI probe type=0x%02x from %s", msg_type, ctx.addr)
            return
        logger.info("IPMI Presence Ping from %s (tag=0x%02x)",
                    ctx.addr, msg_tag)
        ctx.event("ipmi_ping", tag=msg_tag)

        pong = bytes([
            0x06, 0x00, 0xff, 0x06,         # RMCP header
            0x00, 0x00, 0x11, 0xbe,         # ASF header
            0x40,                            # Presence Pong
            msg_tag,                         # echo tag
            0x00,                            # reserved
            0x10,                            # data length
            0x00, 0x00, 0x11, 0xbe,         # IANA enterprise
            0x00, 0x00, 0x00, 0x00,         # OEM-defined
            0x81,                            # IPMI supported
            0x00,                            # Supported Interactions
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # reserved
        ])
        ctx.send(pong)
