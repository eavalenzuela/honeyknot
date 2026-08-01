"""JDWP honeypot on TCP/8000 — an exposed Java debugger is remote code execution.

The Java Debug Wire Protocol has no authentication step at all: anyone who
completes the 14-byte handshake gets full control of the VM. That is the whole
of `jdwp-shellifier` — attach, `ClassesBySignature` for `Ljava/lang/Runtime;`,
plant a breakpoint on a method that is guaranteed to be hit, wait for the
suspend, then `invokeMethod` on `exec` with a command line. Cryptominer crews
sweep 8000/8787/5005 looking for a debug port someone left open in production.

So we answer. Echoing the handshake and returning plausible replies to the
VirtualMachine command set keeps the tool walking its own attack path, and the
step we actually care about is the last one: the `invokeMethod` data carries the
attacker's command string in the clear, so we scrape every printable run out of
it before returning an empty reply and handing them nothing.

Packet framing (all big-endian):
    length(4)  — includes the 11-byte header
    id(4)
    flags(1)   — bit 0x80 set means REPLY, clear means COMMAND
  COMMAND:  command_set(1) command(1) data...
  REPLY:    error_code(2) data...
A JDWP string is u4 length + that many modified-UTF8 bytes.

Event fields avoid the keys `name`, `protocol`, `peer`, `port` and `transport`:
the JSONL sink already sets those on every record, so a handler field with one
of those keys is a duplicate-keyword TypeError at emit time. Hence
`command_name=` on jdwp_command.

`exploit_attempt` is emitted in the same shape as the capture pipeline's
(via `exploits.as_event_fields`) so one query finds every exploit event.
"""

from __future__ import annotations

import logging
import struct

from honeyknot.exploits import as_event_fields, synthetic_hit
from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.jdwp")

HANDSHAKE = b"JDWP-Handshake"
HEADER_LEN = 11
MAX_PACKET = 1 << 20  # 1 MiB — anything larger is not a real debugger
REPLY_FLAG = 0x80

DEFAULT_DESCRIPTION = "Java Debug Wire Protocol (Reference Implementation) version 1.8"
DEFAULT_VM_VERSION = "1.8.0_181"
DEFAULT_VM_NAME = "OpenJDK 64-Bit Server VM"

# Stable fake reference-type id handed back for every class lookup. Real ids are
# opaque VM pointers, so any consistent non-zero value is believable.
FAKE_TYPE_ID = 0x0000_0000_DEAD_BEEF

CMD_SET_VIRTUAL_MACHINE = 1
CMD_SET_CLASS_TYPE = 3
CMD_SET_OBJECT_REFERENCE = 9
CMD_SET_EVENT_REQUEST = 15

COMMAND_SETS = {
    1: "VirtualMachine",
    2: "ReferenceType",
    3: "ClassType",
    4: "ArrayType",
    5: "InterfaceType",
    6: "Method",
    8: "Field",
    9: "ObjectReference",
    10: "StringReference",
    11: "ThreadReference",
    12: "ThreadGroupReference",
    13: "ArrayReference",
    14: "ClassLoaderReference",
    15: "EventRequest",
    16: "StackFrame",
    17: "ClassObjectReference",
    64: "Event",
}

COMMAND_NAMES = {
    (1, 1): "Version",
    (1, 2): "ClassesBySignature",
    (1, 3): "AllClasses",
    (1, 4): "AllThreads",
    (1, 5): "TopLevelThreadGroups",
    (1, 6): "Dispose",
    (1, 7): "IDSizes",
    (1, 8): "Suspend",
    (1, 9): "Resume",
    (1, 10): "Exit",
    (1, 11): "CreateString",
    (1, 12): "Capabilities",
    (1, 13): "ClassPaths",
    (1, 17): "Capabilities",
    (1, 29): "CapabilitiesNew",
    (2, 1): "Signature",
    (2, 3): "Modifiers",
    (2, 5): "Methods",
    (3, 1): "Superclass",
    (3, 3): "InvokeMethod",
    (3, 4): "NewInstance",
    (9, 1): "ReferenceType",
    (9, 6): "InvokeMethod",
    (11, 1): "Name",
    (11, 2): "Suspend",
    (11, 3): "Resume",
    (15, 1): "Set",
    (15, 2): "Clear",
    (64, 100): "Composite",
}

# Printable-run scraping limits for invokeMethod payloads.
MIN_RUN = 4
MAX_RUNS = 20
MAX_RUN_LEN = 200


class JDWPHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        # The debugger client speaks first — we send nothing until it does.
        ctx.state["buffer"] = bytearray()
        ctx.state["handshake_done"] = False
        ctx.state["packets"] = 0

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)

        if not ctx.state.get("handshake_done"):
            if len(buf) < len(HANDSHAKE):
                return  # handshake split across reads — wait for the rest
            if bytes(buf[:len(HANDSHAKE)]) != HANDSHAKE:
                ctx.request_logger.info(
                    "%s: jdwp bad handshake, %d bytes (head=%s)",
                    ctx.addr, len(buf), bytes(buf[:16]).hex())
                ctx.close()
                return
            del buf[:len(HANDSHAKE)]
            ctx.state["handshake_done"] = True
            await ctx.send(HANDSHAKE)
            ctx.request_logger.info("%s: jdwp handshake echoed (%d bytes)",
                                    ctx.addr, len(HANDSHAKE))
            ctx.event("jdwp_handshake", bytes=len(HANDSHAKE))

        while len(buf) >= HEADER_LEN and not ctx.closed:
            length, packet_id, flags = struct.unpack(">IIB", buf[:9])
            if length < HEADER_LEN or length > MAX_PACKET:
                ctx.request_logger.info(
                    "%s: jdwp bogus packet length %d (head=%s)",
                    ctx.addr, length, bytes(buf[:16]).hex())
                ctx.close()
                return
            if len(buf) < length:
                return  # partial packet
            packet = bytes(buf[:length])
            del buf[:length]  # length >= HEADER_LEN, so we always make progress
            await self._handle_packet(packet, packet_id, flags, ctx)

    async def _handle_packet(self, packet: bytes, packet_id: int,
                             flags: int, ctx: ConnectionContext) -> None:
        payload = packet[HEADER_LEN:]
        if flags & REPLY_FLAG:
            # Clients rarely send replies; log the shape and move on.
            ctx.request_logger.info(
                "%s: jdwp reply id=%d %d bytes (head=%s)",
                ctx.addr, packet_id, len(payload), payload[:16].hex())
            return

        command_set = packet[9]
        command = packet[10]
        name = _command_name(command_set, command)
        ctx.state["packets"] = ctx.state.get("packets", 0) + 1
        ctx.request_logger.info(
            "%s: jdwp %s (set=%d cmd=%d) id=%d %d bytes (head=%s)",
            ctx.addr, name, command_set, command, packet_id,
            len(payload), payload[:16].hex())
        ctx.event("jdwp_command",
                  command_set=command_set, command=command, command_name=name,
                  id=packet_id, data_bytes=len(payload))

        reply = await self._reply_payload(command_set, command, payload, ctx)
        await ctx.send(_reply_packet(packet_id, reply))

    async def _reply_payload(self, command_set: int, command: int,
                             data: bytes, ctx: ConnectionContext) -> bytes:
        """Build the reply data for a command. Empty payload = 'fine, carry on'."""
        if command_set == CMD_SET_VIRTUAL_MACHINE:
            return self._virtual_machine(command, data, ctx)
        if command_set == CMD_SET_EVENT_REQUEST and command == 1:
            return _event_request_set(data, ctx)
        if ((command_set == CMD_SET_OBJECT_REFERENCE and command == 6)
                or (command_set == CMD_SET_CLASS_TYPE and command == 3)):
            _invoke_method(command_set, command, data, ctx)
            return b""
        return b""

    def _virtual_machine(self, command: int, data: bytes,
                         ctx: ConnectionContext) -> bytes:
        opts = self.config.protocol_opts
        if command == 1:  # Version
            return (
                _jdwp_string(opts.get("description", DEFAULT_DESCRIPTION))
                + struct.pack(">II", 1, 8)  # jdwpMajor / jdwpMinor
                + _jdwp_string(opts.get("vm_version", DEFAULT_VM_VERSION))
                + _jdwp_string(opts.get("vm_name", DEFAULT_VM_NAME))
            )
        if command == 2:  # ClassesBySignature
            signature = _read_jdwp_string(data, 0)
            ctx.event("jdwp_class_lookup", signature=signature)
            ctx.request_logger.info("%s: jdwp class lookup %r", ctx.addr, signature)
            # Claiming the class exists (status 7 = VERIFIED|PREPARED|INITIALIZED)
            # is what makes jdwp-shellifier advance to the breakpoint step.
            return struct.pack(">IBQI", 1, 1, FAKE_TYPE_ID, 7)
        if command in (3, 4):  # AllClasses / AllThreads
            return struct.pack(">I", 0)
        if command == 7:  # IDSizes — fieldID/methodID/objectID/refTypeID/frameID
            return struct.pack(">IIIII", 8, 8, 8, 8, 8)
        if command == 17:  # Capabilities
            return b"\x01" * 7
        if command == 29:  # CapabilitiesNew
            return b"\x01" * 32
        return b""


def _command_name(command_set: int, command: int) -> str:
    set_name = COMMAND_SETS.get(command_set, f"set{command_set}")
    cmd_name = COMMAND_NAMES.get((command_set, command), f"cmd{command}")
    return f"{set_name}.{cmd_name}"


def _event_request_set(data: bytes, ctx: ConnectionContext) -> bytes:
    """EventRequest.Set — the attacker is planting the breakpoint they need hit."""
    event_kind = data[0] if len(data) >= 1 else 0
    suspend_policy = data[1] if len(data) >= 2 else 0
    ctx.request_logger.info("%s: jdwp event request kind=%d suspend=%d (%d bytes)",
                            ctx.addr, event_kind, suspend_policy, len(data))
    ctx.event("jdwp_event_request",
              event_kind=event_kind, suspend_policy=suspend_policy,
              data_bytes=len(data))
    return struct.pack(">I", 1)  # requestID


def _invoke_method(command_set: int, command: int, data: bytes,
                   ctx: ConnectionContext) -> None:
    """invokeMethod is the payload delivery step — scrape the command line out."""
    strings = _ascii_runs(data)
    ctx.request_logger.info("%s: jdwp invokeMethod set=%d cmd=%d %d bytes strings=%r",
                            ctx.addr, command_set, command, len(data), strings[:4])
    ctx.event("jdwp_invoke",
              command_set=command_set, command=command,
              data_bytes=len(data), strings=strings)
    ctx.event("exploit_attempt", **as_event_fields([synthetic_hit(
        id="jdwp-rce", title="JDWP invokeMethod remote code execution",
        category="rce", severity="critical",
        match=strings[0][:160] if strings else "")]))


def _ascii_runs(data: bytes, min_len: int = MIN_RUN,
                max_runs: int = MAX_RUNS, max_len: int = MAX_RUN_LEN) -> list[str]:
    """Every printable-ASCII run of `min_len`+ chars, capped for log sanity."""
    runs: list[str] = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
            continue
        if len(current) >= min_len:
            runs.append(current[:max_len].decode("ascii", errors="replace"))
            if len(runs) >= max_runs:
                return runs
        current.clear()
    if len(current) >= min_len and len(runs) < max_runs:
        runs.append(current[:max_len].decode("ascii", errors="replace"))
    return runs


def _jdwp_string(value: str) -> bytes:
    """u4 length + modified-UTF8 bytes."""
    raw = value.encode("utf-8", errors="replace")
    return struct.pack(">I", len(raw)) + raw


def _read_jdwp_string(data: bytes, offset: int) -> str:
    """Decode a JDWP string at `offset`; returns "" on any truncation."""
    if len(data) < offset + 4:
        return ""
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    start = offset + 4
    if length > len(data) - start:
        return ""
    return data[start:start + length].decode("utf-8", errors="replace")


def _reply_packet(packet_id: int, payload: bytes) -> bytes:
    """REPLY packet: length, echoed id, flags=0x80, error=0, then data."""
    return struct.pack(">IIBH", HEADER_LEN + len(payload), packet_id,
                       REPLY_FLAG, 0) + payload
