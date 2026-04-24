"""Redis honeypot: parse RESP (REdis Serialization Protocol) commands.

Attackers commonly abuse Redis to write a file to disk (SLAVEOF + REPLCONF
+ CONFIG SET dir/dbfilename + BGSAVE / SET with a cron payload). We accept
every command with a plausible ack so the attacker proceeds to upload their
payload, which lands in the raw capture.

RESP grammar we need: inline commands ("PING\\r\\n") and arrays of bulk
strings ("*3\\r\\n$3\\r\\nSET\\r\\n$3\\r\\nfoo\\r\\n$3\\r\\nbar\\r\\n").
"""

import logging

from honeyknot.protocols.base import ConnectionContext, ProtocolHandler

logger = logging.getLogger("honeyknot.protocols.redis")

DEFAULT_VERSION = "5.0.7"


class RedisHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        ctx.state["buffer"] = b""
        ctx.state["version"] = self.config.protocol_opts.get(
            "version", DEFAULT_VERSION,
        )

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.request_logger.info("%s: %s", ctx.addr, data)
        ctx.state["buffer"] += data

        while ctx.state["buffer"] and not ctx.closed:
            consumed, cmd = _parse_command(ctx.state["buffer"])
            if consumed == 0:
                # Need more data.
                return
            ctx.state["buffer"] = ctx.state["buffer"][consumed:]
            if cmd is None:
                # Malformed; drop buffer to avoid infinite loop.
                ctx.state["buffer"] = b""
                await ctx.send(b"-ERR Protocol error\r\n")
                return
            await self._dispatch(cmd, ctx)

    async def _dispatch(self, cmd: list[str], ctx: ConnectionContext) -> None:
        if not cmd:
            return
        op = cmd[0].upper()
        logger.info("Redis cmd from %s: %s", ctx.addr, cmd)

        if op == "PING":
            await ctx.send(b"+PONG\r\n")
        elif op == "ECHO" and len(cmd) > 1:
            payload = cmd[1].encode("utf-8", errors="replace")
            await ctx.send(f"${len(payload)}\r\n".encode() + payload + b"\r\n")
        elif op == "AUTH":
            await ctx.send(b"+OK\r\n")
        elif op == "INFO":
            info = (
                f"# Server\r\nredis_version:{ctx.state['version']}\r\n"
                f"redis_mode:standalone\r\nos:Linux\r\n"
                f"# Clients\r\nconnected_clients:1\r\n"
            ).encode()
            await ctx.send(f"${len(info)}\r\n".encode() + info + b"\r\n")
        elif op == "CONFIG":
            if len(cmd) > 1 and cmd[1].upper() == "GET":
                # Return empty array — attackers typically ignore the contents.
                await ctx.send(b"*0\r\n")
            else:
                await ctx.send(b"+OK\r\n")
        elif op == "QUIT":
            await ctx.send(b"+OK\r\n")
            ctx.close()
        elif op in ("SET", "SLAVEOF", "REPLICAOF", "REPLCONF",
                    "BGSAVE", "SAVE", "FLUSHALL", "FLUSHDB",
                    "SELECT", "CLIENT", "HELLO", "COMMAND"):
            await ctx.send(b"+OK\r\n")
        elif op == "GET":
            await ctx.send(b"$-1\r\n")  # nil
        elif op == "DBSIZE":
            await ctx.send(b":0\r\n")
        else:
            await ctx.send(b"+OK\r\n")


def _parse_command(buf: bytes) -> tuple[int, list[str] | None]:
    """Parse one RESP command from the head of buf.

    Returns (bytes_consumed, command) or (0, None) if more data is needed.
    Returns (consumed, None) for a malformed frame so the caller can reset.
    """
    if not buf:
        return 0, None
    if buf[0:1] == b"*":
        return _parse_array(buf)
    # Inline command: a single CRLF-terminated line, whitespace-split.
    idx = buf.find(b"\r\n")
    if idx == -1:
        return 0, None
    line = buf[:idx].decode("utf-8", errors="replace")
    return idx + 2, line.split()


def _parse_array(buf: bytes) -> tuple[int, list[str] | None]:
    idx = buf.find(b"\r\n")
    if idx == -1:
        return 0, None
    try:
        count = int(buf[1:idx])
    except ValueError:
        return idx + 2, None
    pos = idx + 2
    items: list[str] = []
    for _ in range(count):
        if pos >= len(buf) or buf[pos:pos + 1] != b"$":
            return 0, None
        end = buf.find(b"\r\n", pos)
        if end == -1:
            return 0, None
        try:
            length = int(buf[pos + 1:end])
        except ValueError:
            return end + 2, None
        start = end + 2
        if start + length + 2 > len(buf):
            return 0, None
        items.append(buf[start:start + length].decode("utf-8", errors="replace"))
        pos = start + length + 2
    return pos, items
