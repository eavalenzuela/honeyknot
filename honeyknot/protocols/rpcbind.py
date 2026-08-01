"""rpcbind/portmap honeypot on UDP/111 — log RPC recon, never amplify.

rpcbind is a reconnaissance goldmine: a single DUMP call enumerates every
RPC service on the host (NFS exports, mountd, ypserv, statd, all with
their live ports), so scanners hit it constantly to map lateral-movement
targets. It is also one of the internet's favourite reflection vectors —
a ~56-byte DUMP call returns a multi-kilobyte map list, and CALLIT lets a
spoofed source bounce requests through us to other RPC programs. We
answer the harmless calls (NULL, GETPORT with "not registered"), log the
interesting ones (DUMP, CALLIT) in full, and enforce a single invariant
in one place: no reply ever exceeds the request that triggered it.

ONC RPC over UDP (RFC 5531), all big-endian:
    call:  xid:u4 msg_type:u4(0) rpcvers:u4(2) prog:u4 vers:u4 proc:u4
           cred(flavor:u4 len:u4 opaque pad4) verf(same) args...
    reply: xid:u4 msg_type:u4(1) reply_stat:u4(0=MSG_ACCEPTED)
           verf(flavor:u4=0 len:u4=0) accept_stat:u4 results...
"""

from __future__ import annotations

import struct

from honeyknot.protocols.base import DatagramContext, ProtocolHandler

MSG_CALL = 0
MSG_REPLY = 1
RPC_VERSION = 2
PROG_PORTMAP = 100000

PROC_NULL = 0
PROC_GETPORT = 3
PROC_DUMP = 4
PROC_CALLIT = 5

ACCEPT_SUCCESS = 0
ACCEPT_PROG_UNAVAIL = 1
ACCEPT_PROC_UNAVAIL = 2

# RFC 5531: opaque auth bodies are capped at 400 bytes.
MAX_AUTH_BODY = 400

PROGRAM_NAMES = {
    100000: "portmapper",
    100003: "nfs",
    100005: "mountd",
    100011: "rquotad",
    100021: "nlockmgr",
    100024: "status",
    100227: "nfs_acl",
    391002: "sgi_fam",
}

PROC_NAMES = {
    0: "NULL",
    1: "SET",
    2: "UNSET",
    3: "GETPORT",
    4: "DUMP",
    5: "CALLIT",
    8: "GETSTAT",
}


def _skip_opaque_auth(data: bytes, pos: int) -> int | None:
    """Skip one opaque_auth (flavor + length + body padded to 4). None if bad."""
    if pos + 8 > len(data):
        return None
    length = int.from_bytes(data[pos + 4:pos + 8], "big")
    if length > MAX_AUTH_BODY:
        return None
    end = pos + 8 + ((length + 3) & ~3)
    if end > len(data):
        return None
    return end


def _parse_call(data: bytes) -> dict | None:
    """Best-effort parse of an ONC RPC v2 CALL. None if malformed / not a call."""
    if len(data) < 24:
        return None
    xid, msg_type, rpcvers, prog, vers, proc = struct.unpack(">6I", data[:24])
    if msg_type != MSG_CALL or rpcvers != RPC_VERSION:
        return None
    pos = _skip_opaque_auth(data, 24)        # credential
    if pos is None:
        return None
    pos = _skip_opaque_auth(data, pos)       # verifier
    if pos is None:
        return None
    return {"xid": xid, "prog": prog, "vers": vers, "proc": proc,
            "args": data[pos:]}


def _accepted_reply(xid: int, accept_stat: int, results: bytes = b"") -> bytes:
    """xid + REPLY + MSG_ACCEPTED + null verifier + accept_stat + results."""
    return struct.pack(">6I", xid, MSG_REPLY, 0, 0, 0, accept_stat) + results


class RPCBindHandler(ProtocolHandler):
    async def on_datagram(self, data: bytes, ctx: DatagramContext) -> None:
        call = _parse_call(data)
        if call is None:
            # Malformed or not a v2 CALL. Reply with nothing: an error reply
            # to an unverifiable packet is a free amplification primitive.
            ctx.request_logger.info(
                "%s: rpcbind malformed/non-call datagram %d bytes head=%s — dropped",
                ctx.addr, len(data), data[:16].hex())
            return

        prog_name = PROGRAM_NAMES.get(call["prog"], "unknown")
        proc_name = PROC_NAMES.get(call["proc"], "unknown")
        ctx.request_logger.info(
            "%s: rpcbind call xid=0x%08x prog=%d(%s) vers=%d proc=%d(%s) %d bytes head=%s",
            ctx.addr, call["xid"], call["prog"], prog_name, call["vers"],
            call["proc"], proc_name, len(data), data[:16].hex())
        ctx.event("rpc_call",
                  xid=call["xid"],
                  program=call["prog"],
                  program_name=prog_name,
                  version=call["vers"],
                  procedure=call["proc"],
                  procedure_name=proc_name,
                  bytes=len(data))

        if call["prog"] != PROG_PORTMAP:
            # rpcbind only serves program 100000; anything else gets the
            # realistic PROG_UNAVAIL — if it fits the size budget.
            self._send_bounded(ctx, _accepted_reply(call["xid"], ACCEPT_PROG_UNAVAIL), data)
            return

        if call["proc"] == PROC_NULL:
            # 24-byte accepted reply, always smaller than the 40-byte-min call.
            self._send_bounded(ctx, _accepted_reply(call["xid"], ACCEPT_SUCCESS), data)
        elif call["proc"] == PROC_GETPORT:
            self._handle_getport(call, data, ctx)
        elif call["proc"] == PROC_DUMP:
            self._handle_dump(call, data, ctx)
        elif call["proc"] == PROC_CALLIT:
            self._handle_callit(call, ctx)
        else:
            # SET / UNSET / GETSTAT / anything else: procedure unavailable.
            self._send_bounded(ctx, _accepted_reply(call["xid"], ACCEPT_PROC_UNAVAIL), data)

    def _handle_getport(self, call: dict, data: bytes, ctx: DatagramContext) -> None:
        args = call["args"]
        q_prog = q_vers = q_prot = 0
        if len(args) >= 12:
            q_prog, q_vers, q_prot = struct.unpack(">3I", args[:12])
        q_proto = {6: "tcp", 17: "udp"}.get(q_prot, str(q_prot))
        ctx.event("rpc_getport",
                  query_program=q_prog,
                  query_program_name=PROGRAM_NAMES.get(q_prog, "unknown"),
                  query_version=q_vers,
                  query_protocol=q_proto)
        # Default port 0 = "not registered": realistic for a hardened host and
        # non-amplifying. Operators may steer attackers to another honeypot
        # port via getport_port.
        port = self.config.protocol_opts.get("getport_port", 0)
        if not isinstance(port, int) or not 0 <= port <= 65535:
            port = 0
        reply = _accepted_reply(call["xid"], ACCEPT_SUCCESS, struct.pack(">I", port))
        self._send_bounded(ctx, reply, data)

    def _handle_dump(self, call: dict, data: bytes, ctx: DatagramContext) -> None:
        # DUMP is *the* rpcbind amplification vector: a real map list is
        # multi-kilobyte. We never emit a populated list — at most a 28-byte
        # empty one (value_follows = 0), and only when it fits the budget.
        ctx.event("rpc_dump_refused", bytes=len(data))
        reply = _accepted_reply(call["xid"], ACCEPT_SUCCESS, struct.pack(">I", 0))
        self._send_bounded(ctx, reply, data)

    def _handle_callit(self, call: dict, ctx: DatagramContext) -> None:
        # CALLIT proxies a call to another local RPC program — the RPC
        # equivalent of SSRF, and a known amplifier. Log the inner target,
        # send nothing.
        args = call["args"]
        inner_prog = inner_vers = inner_proc = 0
        if len(args) >= 12:
            inner_prog, inner_vers, inner_proc = struct.unpack(">3I", args[:12])
        ctx.event("rpc_callit",
                  program=inner_prog,
                  program_name=PROGRAM_NAMES.get(inner_prog, "unknown"),
                  version=inner_vers,
                  procedure=inner_proc)

    def _send_bounded(self, ctx: DatagramContext, reply: bytes, request: bytes) -> None:
        """Single chokepoint for the non-amplification invariant: a reply is
        sent only if it is no larger than the request that triggered it."""
        if len(reply) > len(request):
            ctx.request_logger.info(
                "%s: rpcbind reply suppressed (%d > %d bytes) — no amplification",
                ctx.addr, len(reply), len(request))
            return
        ctx.send(reply)
