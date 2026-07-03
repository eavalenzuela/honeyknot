"""NTP honeypot on UDP/123 — answer client queries, refuse mon/control.

Mode-3 (client) requests get a plausible mode-4 (server) reply of exactly
the same 48-byte size, so we never amplify. Mode-6 (control) and mode-7
(private — i.e. the classic `monlist` reflection/DDoS vector) requests are
logged and dropped: replying would turn us into an amplifier, which is
precisely what this project exists to *avoid* being.

First byte of every NTP packet: LI(2) | VN(3) | Mode(3).
"""

from __future__ import annotations

import logging
import struct
import time

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.ntp")

MODE_CLIENT = 3
MODE_SERVER = 4
MODE_CONTROL = 6
MODE_PRIVATE = 7

# Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
NTP_UNIX_DELTA = 2208988800


def _ntp_now() -> bytes:
    """Current time as an 8-byte NTP timestamp (32.32 fixed point)."""
    now = time.time() + NTP_UNIX_DELTA
    seconds = int(now)
    frac = int((now - seconds) * (1 << 32))
    return struct.pack(">II", seconds & 0xFFFFFFFF, frac & 0xFFFFFFFF)


class NTPHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        if len(data) < 1:
            return
        li_vn_mode = data[0]
        version = (li_vn_mode >> 3) & 0x07
        mode = li_vn_mode & 0x07

        if mode in (MODE_CONTROL, MODE_PRIVATE):
            kind = "control" if mode == MODE_CONTROL else "private"
            logger.info("NTP %s query from %s (mode=%d) — dropped (no amplify)",
                        kind, ctx.addr, mode)
            ctx.event(f"ntp_{kind}", mode=mode, version=version)
            return

        if mode != MODE_CLIENT or len(data) < 48:
            logger.info("NTP mode=%d from %s ignored", mode, ctx.addr)
            return

        logger.info("NTP client query from %s (v%d)", ctx.addr, version)
        ctx.event("ntp_request", version=version)

        # Echo the client's transmit timestamp as our originate timestamp.
        client_tx = data[40:48]
        now = _ntp_now()
        li_vn_mode_out = (version << 3) | MODE_SERVER
        reply = struct.pack(">BBbb", li_vn_mode_out, 2, 3, -20)  # stratum 2
        reply += b"\x00\x00\x00\x00"    # root delay
        reply += b"\x00\x00\x08\x00"    # root dispersion
        reply += b"LOCL"                 # reference identifier
        reply += now                     # reference timestamp
        reply += client_tx               # originate timestamp (echoed)
        reply += now                     # receive timestamp
        reply += now                     # transmit timestamp
        # reply is exactly 48 bytes — never larger than the request.
        ctx.send(reply)
