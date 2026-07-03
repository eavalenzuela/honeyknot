"""ADB honeypot on TCP/5555 — Android Debug Bridge over TCP.

Exposed ADB daemons are a favorite of ADB.Miner / Trinity-class botnets:
they connect, complete the `A_CNXN` handshake, `A_OPEN` a `shell:` stream,
and drop a coin miner. We speak just enough of the framing to finish the
handshake and then log every `A_OPEN` destination (the shell command line)
the attacker asks for — then close the stream so they get nothing back.

ADB message header (little-endian, 24 bytes):
    command(4) arg0(4) arg1(4) data_length(4) data_check(4) magic(4)
`magic` is `command XOR 0xFFFFFFFF`. `data_check` is the 32-bit sum of the
payload bytes (modern adb ignores it). `data_length` bytes of payload follow.
"""

from __future__ import annotations

import logging
import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.adb")

A_CNXN = 0x4E584E43
A_OPEN = 0x4E45504F
A_OKAY = 0x59414B4F
A_WRTE = 0x45545257
A_CLSE = 0x45534C43
A_AUTH = 0x48545541

HEADER_LEN = 24
MAX_PAYLOAD = 256 * 1024
CONNECT_VERSION = 0x01000000
DEFAULT_BANNER = ("device::ro.product.name=honeyknot;ro.product.model=hk;"
                  "ro.product.device=hk;features=cmd,shell_v2")


class ADBHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)
        while len(buf) >= HEADER_LEN and not ctx.closed:
            command, arg0, arg1, dlen, _check, magic = struct.unpack(
                "<IIIIII", buf[:HEADER_LEN])
            if magic != (command ^ 0xFFFFFFFF) or dlen > MAX_PAYLOAD:
                # Not real ADB framing — drop the connection.
                ctx.close()
                return
            if len(buf) < HEADER_LEN + dlen:
                return  # wait for the rest of the payload
            payload = bytes(buf[HEADER_LEN:HEADER_LEN + dlen])
            del buf[:HEADER_LEN + dlen]
            await self._handle(command, arg0, arg1, payload, ctx)

    async def _handle(self, command: int, arg0: int, arg1: int,
                      payload: bytes, ctx: ConnectionContext) -> None:
        if command in (A_CNXN, A_AUTH):
            # Answer both the initial connect and any auth attempt with our
            # own CNXN banner so the client proceeds to the interesting part.
            if command == A_CNXN:
                system = payload.split(b"\x00", 1)[0].decode(
                    "utf-8", errors="replace")
                logger.info("ADB CNXN from %s: %s", ctx.addr, system)
                ctx.event("adb_connect", system=system,
                          version=arg0, maxdata=arg1)
            banner = self.config.protocol_opts.get("banner", DEFAULT_BANNER)
            await ctx.send(_msg(A_CNXN, CONNECT_VERSION, MAX_PAYLOAD,
                                banner.encode() + b"\x00"))
        elif command == A_OPEN:
            dest = payload.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            local_id = arg0
            logger.info("ADB OPEN from %s: %r", ctx.addr, dest)
            ctx.event("adb_open", destination=dest)
            # Accept the stream (OKAY) so the full command line arrives, then
            # immediately close it — the attacker reveals intent, gets no shell.
            our_id = 1
            await ctx.send(_msg(A_OKAY, our_id, local_id, b""))
            await ctx.send(_msg(A_CLSE, our_id, local_id, b""))
        elif command == A_WRTE:
            # Acknowledge writes so a chatty client keeps talking.
            await ctx.send(_msg(A_OKAY, arg1, arg0, b""))
        elif command == A_CLSE:
            ctx.close()


def _msg(command: int, arg0: int, arg1: int, payload: bytes) -> bytes:
    check = sum(payload) & 0xFFFFFFFF
    header = struct.pack("<IIIIII", command, arg0, arg1,
                         len(payload), check, command ^ 0xFFFFFFFF)
    return header + payload
