"""BACnet/IP honeypot on UDP/47808 — Who-Is → I-Am responder.

BACnet/IP frames are BVLC(4) + NPDU(var) + APDU(var). The three message
types scanners send:

  - Who-Is (APDU service 8, unconfirmed request): "any devices in this
    range announce yourselves". We answer with I-Am.
  - Read-Property of Device object's object-name or vendor-name: we log
    the request and send a simple error (we don't synthesize values).
  - Anything else: logged and silently dropped.

I-Am is broadcast on real networks; here we just respond unicast to the
sender. The announced device instance defaults to 1 and is configurable.
"""

from __future__ import annotations

import logging

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.bacnet")

BVLC_TYPE = 0x81            # BACnet/IP
BVLC_ORIGINAL_UNICAST = 0x0A
BVLC_ORIGINAL_BROADCAST = 0x0B

APDU_UNCONFIRMED_REQUEST = 0x10
SVC_I_AM = 0x00
SVC_WHO_IS = 0x08

DEFAULT_INSTANCE = 1
DEFAULT_VENDOR = 260         # "Honeyknot" — any unused ID is fine for decoy
DEFAULT_MAX_APDU = 1476
DEFAULT_SEG_SUPPORTED = 0    # segmented-both=0


class BACnetHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        if len(data) < 4:
            return
        if data[0] != BVLC_TYPE:
            return
        bvlc_len = int.from_bytes(data[2:4], "big")
        if bvlc_len != len(data):
            logger.info("BACnet length mismatch from %s: claimed=%d got=%d",
                        ctx.addr, bvlc_len, len(data))
            return

        # Walk past the NPDU. Minimal NPDU: version(1) control(1); optional
        # destination / source address fields are present when control bits
        # are set.
        pos = 4
        if pos + 2 > len(data):
            return
        npdu_version = data[pos]
        control = data[pos + 1]
        pos += 2
        if npdu_version != 0x01:
            return
        if control & 0x20:   # DNET/DLEN/DADR present
            if pos + 3 > len(data):
                return
            dlen = data[pos + 2]
            pos += 3 + dlen
        if control & 0x08:   # SNET/SLEN/SADR present
            if pos + 3 > len(data):
                return
            slen = data[pos + 2]
            pos += 3 + slen
        if control & 0x20:   # hop count follows when DNET was present
            pos += 1
        if control & 0x80:   # NPDU is a network-layer message, not APDU
            return
        if pos >= len(data):
            return

        apdu = data[pos:]
        if not apdu:
            return
        apdu_type = apdu[0] & 0xF0
        if apdu_type != APDU_UNCONFIRMED_REQUEST or len(apdu) < 2:
            logger.info("BACnet APDU type=0x%02x from %s (%d bytes) — "
                        "logged, no reply",
                        apdu_type, ctx.addr, len(apdu))
            ctx.event("bacnet_request",
                      apdu_type=apdu_type, payload=apdu.hex())
            return
        service = apdu[1]

        if service == SVC_WHO_IS:
            logger.info("BACnet Who-Is from %s (%d bytes)", ctx.addr, len(apdu))
            ctx.event("bacnet_request", service="Who-Is",
                      payload=apdu[2:].hex())
            instance = self.config.protocol_opts.get(
                "device_instance", DEFAULT_INSTANCE)
            vendor = self.config.protocol_opts.get(
                "vendor_id", DEFAULT_VENDOR)
            # BACnet I-Am is legitimately larger than a minimal Who-Is;
            # BACnet/IP isn't a standard Internet amplification target
            # (it's a LAN broadcast protocol). We reply unconditionally.
            ctx.send(_build_i_am(instance, vendor))
        else:
            logger.info("BACnet service=0x%02x from %s (%d bytes)",
                        service, ctx.addr, len(apdu))
            ctx.event("bacnet_request", service=f"0x{service:02x}",
                      payload=apdu[2:].hex())


def _build_i_am(instance: int, vendor: int) -> bytes:
    """Build a unicast BACnet/IP I-Am response frame."""
    # APDU: type=Unconfirmed-Request(0x10), service=I-Am(0x00), 4 tagged
    # encodings:
    #   Tag 0xC4 = context tag 12? Actually application tag 12 (BACnetObjectIdentifier)
    #   encoded with tag 0xC4 length 4 | octets (device_object_type=8
    #   shifted into top 10 bits + instance in low 22 bits).
    # We hardcode the shortest valid I-Am.
    object_id_value = (8 << 22) | (instance & 0x3FFFFF)
    apdu = bytes([APDU_UNCONFIRMED_REQUEST, SVC_I_AM])
    apdu += b"\xC4" + object_id_value.to_bytes(4, "big")
    apdu += b"\x22" + DEFAULT_MAX_APDU.to_bytes(2, "big")
    apdu += b"\x91" + bytes([DEFAULT_SEG_SUPPORTED])
    # Vendor: 1-byte if < 256, else 2-byte encoding with length nibble
    if vendor < 256:
        apdu += b"\x21" + bytes([vendor])
    else:
        apdu += b"\x22" + vendor.to_bytes(2, "big")

    # NPDU: version=1, control=0 (no DNET/SNET, expecting-reply=0, priority=0)
    npdu = b"\x01\x00"

    payload = npdu + apdu
    total = 4 + len(payload)
    bvlc = bytes([BVLC_TYPE, BVLC_ORIGINAL_UNICAST]) + total.to_bytes(2, "big")
    return bvlc + payload
