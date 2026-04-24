"""Modbus TCP honeypot on TCP/502 — ICS recon attribution.

Scanners running Ethernet-scanning tools (nmap modbus-discover, plcscan,
Shodan) send Read Holding Registers / Read Coils to fingerprint real PLCs.
We answer with plausible register values so we show up as a real device,
log every function code + address range, and drop on unknown functions.

MBAP header (7 bytes):
    TransactionID(2) | ProtocolID(2) = 0 | Length(2) | UnitID(1)
Then PDU: function code (1) + request-specific payload.
"""

from __future__ import annotations

import logging
import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.modbus")


class ModbusHandler(ProtocolHandler):
    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.state.setdefault("buffer", bytearray())
        ctx.state["buffer"].extend(data)

        while len(ctx.state["buffer"]) >= 8 and not ctx.closed:
            trans_id, proto_id, length, unit_id = struct.unpack(
                ">HHHB", ctx.state["buffer"][:7],
            )
            if proto_id != 0 or length > 260 or length < 2:
                logger.info("Modbus malformed frame from %s: proto=%d len=%d",
                            ctx.addr, proto_id, length)
                ctx.close()
                return
            total = 6 + length  # MBAP header up through length is 6 bytes
            if len(ctx.state["buffer"]) < total:
                return  # need more bytes
            frame = bytes(ctx.state["buffer"][:total])
            ctx.state["buffer"] = ctx.state["buffer"][total:]
            await self._handle_frame(trans_id, unit_id, frame[7:], ctx)

    async def _handle_frame(self, trans_id: int, unit_id: int,
                            pdu: bytes, ctx: ConnectionContext) -> None:
        if not pdu:
            return
        fc = pdu[0]
        logger.info("Modbus fc=0x%02x from %s (trans=%d unit=%d)",
                    fc, ctx.addr, trans_id, unit_id)
        ctx.event("modbus_request",
                  function=fc, unit=unit_id, transaction=trans_id,
                  payload=pdu[1:].hex())

        if fc in (1, 2) and len(pdu) >= 5:           # Read Coils / Discrete Inputs
            _, quantity = struct.unpack(">HH", pdu[1:5])
            byte_count = (quantity + 7) // 8
            body = bytes([byte_count]) + b"\x00" * byte_count
            await self._reply(trans_id, unit_id, fc, body, ctx)
        elif fc in (3, 4) and len(pdu) >= 5:         # Read Holding / Input Registers
            _, quantity = struct.unpack(">HH", pdu[1:5])
            if quantity < 1 or quantity > 125:
                await self._exception(trans_id, unit_id, fc, 3, ctx)
                return
            body = bytes([quantity * 2]) + b"\x00\x01" * quantity
            await self._reply(trans_id, unit_id, fc, body, ctx)
        elif fc in (5, 6) and len(pdu) >= 5:         # Write Single Coil/Register
            await self._reply(trans_id, unit_id, fc, pdu[1:5], ctx)
        elif fc == 43 and len(pdu) >= 3:             # Read Device Identification
            # Basic identification: VendorName / ProductCode / Revision
            objects = [
                (0x00, b"Honeyknot"),
                (0x01, b"HK-MB-1"),
                (0x02, b"1.0"),
            ]
            body = bytes([0x0E, pdu[2], 0x01, 0x00, 0x00, len(objects)])
            for obj_id, s in objects:
                body += bytes([obj_id, len(s)]) + s
            await self._reply(trans_id, unit_id, fc, body, ctx)
        else:
            await self._exception(trans_id, unit_id, fc, 1, ctx)

    async def _reply(self, trans_id: int, unit_id: int, fc: int,
                     body: bytes, ctx: ConnectionContext) -> None:
        pdu = bytes([fc]) + body
        mbap = struct.pack(">HHHB", trans_id, 0, 1 + len(pdu), unit_id)
        await ctx.send(mbap + pdu)

    async def _exception(self, trans_id: int, unit_id: int, fc: int,
                         code: int, ctx: ConnectionContext) -> None:
        pdu = bytes([fc | 0x80, code])
        mbap = struct.pack(">HHHB", trans_id, 0, 1 + len(pdu), unit_id)
        await ctx.send(mbap + pdu)
