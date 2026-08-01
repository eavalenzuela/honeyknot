"""ZooKeeper honeypot on TCP/2181 — answers the "four letter word" recon.

An exposed ZooKeeper is a full cluster-configuration disclosure and a
pivot into whatever Kafka/HBase/Mesos estate it coordinates; its admin
commands also make it a reflection/amplification surface. Scanners
fingerprint it with the "four letter word" commands (ruok/stat/envi/...)
before deciding whether to escalate — answering those realistically is
what makes the scanner record the host as live and come back with the
real tooling, which lands in the raw capture. We also accept the binary
client handshake (ConnectRequest) and ack session pings so follow-up
requests keep flowing while we log each opcode.
"""

from __future__ import annotations

import logging
import secrets
import struct

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.zookeeper")

DEFAULT_VERSION = ("3.4.13-2d71af4dbe22557fda74f9a9b4309b15a7487f03, "
                   "built on 06/29/2018 04:05 GMT")
DEFAULT_MODE = "standalone"
DEFAULT_NODE_COUNT = 27
MAX_FRAME = 1024 * 1024  # reject binary frames declaring more than 1 MiB

FOUR_LETTER_WORDS = {
    "ruok", "stat", "srvr", "conf", "envi", "cons", "mntr", "dump",
    "wchs", "wchc", "wchp", "isro", "crst", "srst", "gtmk", "stmk",
}

OP_PING = 11
OPCODE_NAMES = {
    1: "create", 2: "delete", 3: "exists", 4: "getData", 5: "setData",
    8: "getChildren", 11: "ping", 12: "getChildren2", 101: "multi",
}


class ZooKeeperHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] = bytearray()
        ctx.state["wire"] = None  # None until classified, then "binary"
        ctx.state["connected"] = False

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        buf = ctx.state.setdefault("buffer", bytearray())
        buf.extend(data)
        if len(buf) > MAX_FRAME + 8:
            ctx.request_logger.info("%s: zookeeper buffer cap exceeded, closing", ctx.addr)
            ctx.close()
            return
        while not ctx.closed:
            if ctx.state.get("wire") is None:
                if len(buf) < 4:
                    return  # tolerate a client that sends 2 bytes and stops
                if all(0x61 <= b <= 0x7A for b in buf[:4]):
                    cmd = bytes(buf[:4]).decode("ascii")
                    del buf[:]  # real server closes after a 4lw; drop the rest
                    await self._four_letter(cmd, ctx)
                    ctx.close()
                    return
                ctx.state["wire"] = "binary"
            if not await self._binary_frame(ctx):
                return

    # ---- binary client protocol -------------------------------------

    async def _binary_frame(self, ctx: ConnectionContext) -> bool:
        """Consume one length-prefixed frame. Returns False if more data
        is needed (truncated frame) or the connection was closed."""
        buf = ctx.state["buffer"]
        if len(buf) < 4:
            return False
        length = int.from_bytes(buf[:4], "big")
        if length > MAX_FRAME:
            ctx.request_logger.info(
                "%s: zookeeper frame declares %d bytes, closing", ctx.addr, length)
            ctx.close()
            return False
        if len(buf) < 4 + length:
            return False  # truncated frame — wait for the rest
        body = bytes(buf[4:4 + length])
        del buf[:4 + length]
        if not ctx.state.get("connected"):
            ctx.state["connected"] = True
            await self._connect_request(body, ctx)
        else:
            await self._request_frame(body, ctx)
        return True

    async def _connect_request(self, body: bytes, ctx: ConnectionContext) -> None:
        """Parse a ConnectRequest as far as the bytes allow and fake a
        successful ConnectResponse so the client starts issuing requests."""
        proto_ver = _u32(body, 0)
        # lastZxidSeen (u8) sits at offset 4; we don't need it.
        timeout_ms = _u32(body, 12)
        session_id = _u64(body, 16)
        ctx.request_logger.info(
            "%s: zookeeper connect proto=%s timeout=%s session=%s",
            ctx.addr, proto_ver, timeout_ms, session_id)
        ctx.event("zookeeper_connect",
                  protocol_version=proto_ver,
                  timeout_ms=timeout_ms,
                  session_id=session_id)
        granted = timeout_ms if timeout_ms and 0 < timeout_ms <= 3_600_000 else 30000
        fake_sid = (0x100 << 40) | secrets.randbits(32)  # non-zero, plausible
        resp = (struct.pack(">iiq", 0, granted, fake_sid)
                + struct.pack(">i", 16) + secrets.token_bytes(16))
        await ctx.send(struct.pack(">I", len(resp)) + resp)

    async def _request_frame(self, body: bytes, ctx: ConnectionContext) -> None:
        xid = _i32(body, 0)
        opcode = _i32(body, 4)
        name = OPCODE_NAMES.get(opcode, "unknown")
        ctx.request_logger.info(
            "%s: zookeeper request xid=%s opcode=%s (%s) %d bytes",
            ctx.addr, xid, opcode, name, len(body))
        ctx.event("zookeeper_request",
                  xid=xid, opcode=opcode, opcode_name=name, bytes=len(body))
        if opcode == OP_PING:
            # ReplyHeader: xid, zxid, err — enough to keep the session alive.
            header = struct.pack(">iqi", xid if xid is not None else -2, 0x9A, 0)
            await ctx.send(struct.pack(">I", len(header)) + header)

    # ---- four letter words ------------------------------------------

    async def _four_letter(self, cmd: str, ctx: ConnectionContext) -> None:
        known = cmd in FOUR_LETTER_WORDS
        ctx.request_logger.info("%s: zookeeper 4lw %r known=%s", ctx.addr, cmd, known)
        logger.info("ZooKeeper 4lw from %s: %s", ctx.addr, cmd)
        ctx.event("zookeeper_command", command=cmd, known=known)
        if not known:
            # Modern ZooKeeper's own reply for non-whitelisted commands.
            await ctx.send(
                f"{cmd} is not executed because it is not in the whitelist.\n".encode())
            return

        opts = self.config.protocol_opts
        version = opts.get("version", DEFAULT_VERSION)
        mode = opts.get("mode", DEFAULT_MODE)
        node_count = opts.get("node_count", DEFAULT_NODE_COUNT)
        addr = ctx.addr
        peer = (f"{addr[0]}:{addr[1]}"
                if isinstance(addr, tuple) and len(addr) >= 2 else str(addr))

        if cmd == "ruok":
            await ctx.send(b"imok")  # no newline — matches the real server
        elif cmd == "isro":
            await ctx.send(b"rw")
        elif cmd in ("stat", "srvr"):
            lines = [f"Zookeeper version: {version}"]
            if cmd == "stat":
                lines += ["Clients:",
                          f" /{peer}[0](queued=0,recved=1,sent=0)",
                          ""]
            lines += [
                "Latency min/avg/max: 0/0/12",
                "Received: 2891",
                "Sent: 2890",
                "Connections: 1",
                "Outstanding: 0",
                "Zxid: 0x9a",
                f"Mode: {mode}",
                f"Node count: {node_count}",
            ]
            await ctx.send(("\n".join(lines) + "\n").encode())
        elif cmd == "conf":
            await ctx.send(
                b"clientPort=2181\n"
                b"dataDir=/var/lib/zookeeper/version-2\n"
                b"dataLogDir=/var/lib/zookeeper/version-2\n"
                b"tickTime=2000\n"
                b"maxClientCnxns=60\n"
                b"minSessionTimeout=4000\n"
                b"maxSessionTimeout=40000\n"
                b"serverId=0\n"
            )
        elif cmd == "envi":
            await ctx.send((
                "Environment:\n"
                f"zookeeper.version={version}\n"
                f"host.name={opts.get('hostname', 'zk1')}\n"
                "java.version=1.8.0_181\n"
                "java.vendor=Oracle Corporation\n"
                "java.home=/usr/lib/jvm/java-8-openjdk-amd64/jre\n"
                "java.class.path=/opt/zookeeper/zookeeper-3.4.13.jar:/opt/zookeeper/lib\n"
                "java.io.tmpdir=/tmp\n"
                "os.name=Linux\n"
                "os.arch=amd64\n"
                "os.version=4.15.0-45-generic\n"
                "user.name=zookeeper\n"
                "user.home=/var/lib/zookeeper\n"
                "user.dir=/opt/zookeeper\n"
            ).encode())
        elif cmd == "mntr":
            pairs = [
                ("zk_version", version),
                ("zk_avg_latency", 0),
                ("zk_max_latency", 12),
                ("zk_min_latency", 0),
                ("zk_packets_received", 2891),
                ("zk_packets_sent", 2890),
                ("zk_num_alive_connections", 1),
                ("zk_outstanding_requests", 0),
                ("zk_server_state", mode),
                ("zk_znode_count", node_count),
                ("zk_watch_count", 14),
                ("zk_ephemerals_count", 2),
                ("zk_approximate_data_size", 44022),
                ("zk_open_file_descriptor_count", 46),
                ("zk_max_file_descriptor_count", 4096),
                ("zk_followers", 0),
                ("zk_synced_followers", 0),
                ("zk_pending_syncs", 0),
            ]
            await ctx.send("".join(f"{k}\t{v}\n" for k, v in pairs).encode())
        elif cmd == "cons":
            await ctx.send(f" /{peer}[0](queued=0,recved=1,sent=0)\n\n".encode())
        elif cmd == "dump":
            await ctx.send(
                b"SessionTracker dump:\n"
                b"Session Sets (0):\n"
                b"ephemeral nodes dump:\n"
                b"Sessions with Ephemerals (0):\n")
        elif cmd == "wchs":
            await ctx.send(b"0 connections watching 0 paths\nTotal watches:0\n")
        elif cmd in ("wchc", "wchp"):
            await ctx.send(b"\n")
        elif cmd == "crst":
            await ctx.send(b"Connection stats reset.\n")
        elif cmd == "srst":
            await ctx.send(b"Server stats reset.\n")
        elif cmd in ("gtmk", "stmk"):
            await ctx.send(b"306\n")


def _u32(buf: bytes, off: int) -> int | None:
    if off + 4 > len(buf):
        return None
    return int.from_bytes(buf[off:off + 4], "big")


def _u64(buf: bytes, off: int) -> int | None:
    if off + 8 > len(buf):
        return None
    return int.from_bytes(buf[off:off + 8], "big")


def _i32(buf: bytes, off: int) -> int | None:
    if off + 4 > len(buf):
        return None
    return int.from_bytes(buf[off:off + 4], "big", signed=True)
