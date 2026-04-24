"""MSSQL honeypot on TCP/1433: respond to TDS Pre-Login so tools proceed to
sending their LOGIN7 payload (which contains username/password).

TDS packet layout: 8-byte header (Type, Status, Length, SPID, PacketID, Window)
followed by payload. The Pre-Login payload is a sequence of option records
pointing to offset/length pairs.
"""

import logging
import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.mssql")

TDS_PRELOGIN = 0x12
TDS_LOGIN7 = 0x10
TDS_RESPONSE = 0x04


class MSSQLHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state.setdefault("buffer", b"")
        ctx.state["buffer"] += data

        while len(ctx.state["buffer"]) >= 8:
            packet_type = ctx.state["buffer"][0]
            length = struct.unpack(">H", ctx.state["buffer"][2:4])[0]
            if length < 8 or length > 65535:
                ctx.state["buffer"] = b""
                return
            if len(ctx.state["buffer"]) < length:
                return
            packet = ctx.state["buffer"][:length]
            ctx.state["buffer"] = ctx.state["buffer"][length:]
            await self._handle_packet(packet_type, packet, ctx)
            if ctx.closed:
                return

    async def _handle_packet(self, ptype: int, packet: bytes,
                             ctx: ConnectionContext) -> None:
        if ptype == TDS_PRELOGIN:
            logger.info("MSSQL PRELOGIN from %s (%d bytes)",
                        ctx.addr, len(packet))
            await ctx.send(_build_prelogin_response())
        elif ptype == TDS_LOGIN7:
            logger.info("MSSQL LOGIN7 from %s (%d bytes) — captured",
                        ctx.addr, len(packet))
            # Send a plausible login-failure so the client doesn't block.
            await ctx.send(_build_login_error())
            ctx.close()
        else:
            logger.info("MSSQL packet type=0x%02x from %s len=%d",
                        ptype, ctx.addr, len(packet))
            ctx.close()


def _build_prelogin_response() -> bytes:
    """Single VERSION option + TERMINATOR, payload says SQL Server 12.0."""
    # Option records: each is 1 byte type + 2 bytes offset + 2 bytes length.
    # We emit a VERSION(0x00) option and TERMINATOR(0xFF). Offsets are
    # relative to the start of the option records.
    terminator = b"\xff"
    # VERSION option record: type=0, offset, length=6
    # Offset starts after all records + terminator.
    records_size = 5 + len(terminator)
    version_record = struct.pack(">BHH", 0x00, records_size, 6)
    version_payload = b"\x0c\x00\x08\xcd\x00\x00"  # 12.0.2248
    payload = version_record + terminator + version_payload
    header = struct.pack(">BBHHBB",
                         TDS_RESPONSE, 0x01, 8 + len(payload),
                         0, 1, 0)
    return header + payload


def _build_login_error() -> bytes:
    """TDS response packet with a single ERROR token so clients unblock."""
    # Token 0xAA = ERROR. Structure: Token(1) Length(2) Number(4) State(1)
    # Class(1) MsgLen(2) Msg(UCS-2) ServerLen(1) Server(UCS-2)
    # ProcLen(1) Proc(UCS-2) LineNumber(4).
    msg = "Login failed".encode("utf-16-le")
    server = "honeyknot".encode("utf-16-le")
    token = bytearray()
    token.append(0xAA)
    body = struct.pack("<IBB", 18456, 1, 14)  # error 18456, state 1, class 14
    body += struct.pack("<H", len(msg) // 2) + msg
    body += struct.pack("<B", len(server) // 2) + server
    body += b"\x00"  # proc name empty
    body += struct.pack("<I", 1)  # line number
    token += struct.pack("<H", len(body)) + body
    # DONE token (0xFD): Status(2) CurCmd(2) DoneRowCount(8)
    done = b"\xfd" + struct.pack("<HHQ", 0x0002, 0, 0)
    payload = bytes(token) + done
    header = struct.pack(">BBHHBB",
                         TDS_RESPONSE, 0x01, 8 + len(payload),
                         0, 1, 0)
    return header + payload
