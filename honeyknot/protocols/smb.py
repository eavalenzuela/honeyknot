"""SMB honeypot on TCP/445: reply to SMB1 Negotiate so EternalBlue-style
scanners complete their probe and reveal what they are.

We only answer the SMB1 Negotiate Protocol Request (which most modern
Windows clients still send at the start of negotiation). We reply with a
plausible NT LM 0.12 dialect selection and then capture whatever the
attacker sends next — the interesting bit is their SMB_COM_SESSION_SETUP
or raw Trans2 packets that scanners use to fingerprint MS17-010.

We don't pretend to be a real SMB stack; we just stay alive long enough
to collect one more packet from the peer.
"""

import logging
import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.smb")

SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"


class SMBHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.request_logger.info("%s: %d bytes (head=%s)",
                                ctx.addr, len(data), data[:16].hex())
        ctx.state.setdefault("buffer", b"")
        ctx.state["buffer"] += data

        # Drain complete NetBIOS-framed messages from the buffer.
        # NBSS: Type(1) + Length(24-bit big-endian) + payload.
        while len(ctx.state["buffer"]) >= 4:
            length = int.from_bytes(ctx.state["buffer"][1:4], "big")
            if len(ctx.state["buffer"]) < 4 + length:
                return
            frame = ctx.state["buffer"][4:4 + length]
            ctx.state["buffer"] = ctx.state["buffer"][4 + length:]
            await self._handle_frame(frame, ctx)
            if ctx.closed:
                return

    async def _handle_frame(self, frame: bytes, ctx: ConnectionContext) -> None:
        if frame.startswith(SMB1_MAGIC):
            command = frame[4] if len(frame) > 4 else 0
            if command == 0x72:  # SMB_COM_NEGOTIATE
                await ctx.send(_smb1_negotiate_response(frame))
                ctx.state["negotiated"] = True
                return
        elif frame.startswith(SMB2_MAGIC):
            logger.info("SMB2 frame from %s: cmd=%s",
                        ctx.addr, frame[12:14].hex())
        # Anything after one negotiate round-trip is the prize — logged and
        # captured via the raw sink. Drop the connection so we don't tie up
        # a slot on a protocol we can't actually implement.
        if ctx.state.get("negotiated"):
            ctx.close()


def _smb1_negotiate_response(request: bytes) -> bytes:
    """Build a minimal SMB1 Negotiate response selecting NT LM 0.12 (index 0).

    Copies flags/PID/UID/MID from the request so the client accepts it.
    Layout: NetBIOS frame + SMB header (32) + WordCount(1) + Words(17*2)
    + ByteCount(2) + dummy bytes.
    """
    if len(request) < 32:
        return b""
    # Header
    header = bytearray(32)
    header[0:4] = SMB1_MAGIC
    header[4] = 0x72  # SMB_COM_NEGOTIATE
    header[5:9] = b"\x00\x00\x00\x00"  # NT_STATUS = 0
    header[9] = 0x88  # flags: reply + case-insensitive
    header[10:12] = b"\x01\xc8"  # flags2
    # Copy PID/TID/UID/MID from request
    header[12:14] = request[12:14]  # PidHigh
    header[14:18] = b"\x00" * 4     # Signature (first half)
    header[18:20] = b"\x00" * 2
    header[20:22] = b"\x00" * 2     # Reserved
    header[22:24] = request[22:24]  # TID
    header[24:26] = request[24:26]  # PIDLow
    header[26:28] = request[26:28]  # UID
    header[28:30] = request[28:30]  # MID

    # 17-word parameter block for NT LM 0.12 negotiate response
    params = bytearray(17 * 2)
    struct.pack_into("<H", params, 0, 0)         # DialectIndex = 0
    params[2] = 0x03                              # SecurityMode
    struct.pack_into("<H", params, 3, 50)        # MaxMpxCount
    struct.pack_into("<H", params, 5, 1)         # MaxNumberVcs
    struct.pack_into("<I", params, 7, 16644)     # MaxBufferSize
    struct.pack_into("<I", params, 11, 65536)    # MaxRawSize
    struct.pack_into("<I", params, 15, 0)        # SessionKey
    struct.pack_into("<I", params, 19, 0x800000FD)  # Capabilities
    struct.pack_into("<Q", params, 23, 0)        # SystemTime
    struct.pack_into("<H", params, 31, 0)        # ServerTimeZone
    params[33] = 0                                # ChallengeLength

    byte_block = b""  # empty — attackers tolerate this for fingerprinting

    smb_message = (
        bytes(header)
        + bytes([17])
        + bytes(params)
        + struct.pack("<H", len(byte_block))
        + byte_block
    )
    # NetBIOS Session Service header: type=0, length (24-bit big-endian).
    return b"\x00" + struct.pack(">I", len(smb_message))[1:] + smb_message
