"""Telnet honeypot: IAC negotiation, credential capture, and a fake shell.

Telnet is where IoT botnets live. The session shape is always the same:
brute-force a login, then run a fixed reconnaissance script, then drop a
payload. The old version of this handler stopped after the login and
answered every command with a bare `#`, which meant we collected
credentials and nothing else — the loader checks its own recon output and
hangs up when it doesn't like the answers.

Now the post-login phase runs on `honeyknot.shell`, which answers the whole
Mirai-class fingerprinting sequence convincingly (`/bin/busybox <TOKEN>`,
`cat /proc/mounts`, `cat /bin/echo` for the CPU architecture) so the loader
proceeds to delivery. What it delivers is the point: a `wget`/`tftp` URL
becomes an IOC and, with `--fetch-payloads`, an actual sample; an
`echo -ne '\\x7fELF...' >> .s` echo-loader is reassembled byte-for-byte and
stored as an artifact.

Nothing is executed. Every response comes from a table.
"""

import logging

from honeyknot.exploits import as_event_fields, classify
from honeyknot.protocols.base import ConnectionContext, ProtocolHandler
from honeyknot.shell import ShellSession, parse_heredoc

logger = logging.getLogger("honeyknot.protocols.telnet")

IAC = 0xFF
DO = 0xFD
DONT = 0xFE
WILL = 0xFB
WONT = 0xFC
SB = 0xFA
SE = 0xF0

MAX_LINE_BYTES = 8192
MAX_COMMANDS = 500

DEFAULT_MOTD = (
    "\r\n"
    "BusyBox v1.20.2 (2016-05-13 12:04:31 UTC) built-in shell (ash)\r\n"
    "Enter 'help' for a list of built-in commands.\r\n"
    "\r\n"
)


class TelnetHandler(ProtocolHandler):
    async def on_connect(self, ctx: ConnectionContext) -> None:
        opts = self.config.protocol_opts
        hostname = opts.get("hostname", "localhost")
        ctx.state["hostname"] = hostname
        ctx.state["phase"] = "user"
        ctx.state["line"] = bytearray()
        ctx.state["user"] = None
        ctx.state["attempts"] = 0
        ctx.state["commands"] = 0
        # Minimal IAC negotiation: WILL ECHO, WILL SGA, DO NAWS
        await ctx.send(bytes([IAC, WILL, 0x01, IAC, WILL, 0x03, IAC, DO, 0x1F]))
        await ctx.send(f"\r\n{hostname} login: ".encode())

    async def on_data(self, data: bytes, ctx: ConnectionContext) -> None:
        ctx.request_logger.info("%s: %s", ctx.addr, data)
        stripped = self._strip_iac(data)
        for byte in stripped:
            was_cr = ctx.state.get("last_was_cr", False)
            ctx.state["last_was_cr"] = byte == 0x0D

            if byte in (0x0D, 0x0A):
                # CRLF is one line ending, not two. Without this a real
                # client gets a doubled prompt after every command, which is
                # exactly the kind of tell a careful loader checks for.
                if byte == 0x0A and was_cr:
                    continue
                if ctx.state["line"] or ctx.state.get("phase") == "shell":
                    line = bytes(ctx.state["line"])
                    ctx.state["line"] = bytearray()
                    await self._handle_line(line, ctx)
                if ctx.closed:
                    return
            elif byte in (0x08, 0x7F):
                if ctx.state["line"]:
                    ctx.state["line"].pop()
            elif 0x20 <= byte < 0x7F and len(ctx.state["line"]) < MAX_LINE_BYTES:
                ctx.state["line"].append(byte)

    @staticmethod
    def _strip_iac(data: bytes) -> bytes:
        out = bytearray()
        i = 0
        while i < len(data):
            b = data[i]
            if b == IAC and i + 1 < len(data):
                nxt = data[i + 1]
                if nxt == SB:
                    # Skip to IAC SE
                    end = data.find(bytes([IAC, SE]), i + 2)
                    i = end + 2 if end != -1 else len(data)
                    continue
                if nxt in (DO, DONT, WILL, WONT):
                    i += 3
                    continue
                i += 2
                continue
            out.append(b)
            i += 1
        return bytes(out)

    async def _handle_line(self, line: bytes, ctx: ConnectionContext) -> None:
        text = line.decode("ascii", errors="replace").rstrip()
        phase = ctx.state["phase"]

        if phase == "user":
            if not text:
                await ctx.send(f"\r\n{ctx.state['hostname']} login: ".encode())
                return
            ctx.state["user"] = text
            ctx.state["phase"] = "pass"
            await ctx.send(b"Password: ")
            return

        if phase == "pass":
            await self._check_login(text, ctx)
            return

        await self._run_command(text, ctx)

    async def _check_login(self, password: str, ctx: ConnectionContext) -> None:
        opts = self.config.protocol_opts
        user = ctx.state.get("user")
        ctx.state["attempts"] += 1
        logger.info("Telnet creds from %s: user=%r pass=%r",
                    ctx.addr, user, password)
        ctx.event("credentials", service="telnet",
                  username=user, password=password,
                  attempt=ctx.state["attempts"])

        # Some loaders verify that *wrong* credentials are refused before
        # trusting a host, so `reject_first` makes the honeypot fail a few
        # attempts first. Default 0: accept immediately, which maximizes the
        # number of sessions that reach the payload stage.
        reject_first = int(opts.get("reject_first", 0))
        if ctx.state["attempts"] <= reject_first:
            ctx.state["phase"] = "user"
            ctx.state["user"] = None
            await ctx.send(b"\r\nLogin incorrect\r\n")
            await ctx.send(f"{ctx.state['hostname']} login: ".encode())
            return

        shell = ShellSession(
            hostname=ctx.state["hostname"],
            user=user or "root",
            arch=opts.get("arch", "x86_64"),
            opts=opts,
        )
        ctx.state["shell"] = shell
        ctx.state["phase"] = "shell"
        await ctx.send(b"\r\n")
        await ctx.send(opts.get("motd", DEFAULT_MOTD).encode())
        await ctx.send(shell.prompt)

    async def _run_command(self, text: str, ctx: ConnectionContext) -> None:
        shell: ShellSession = ctx.state["shell"]
        ctx.state["commands"] += 1
        if ctx.state["commands"] > MAX_COMMANDS:
            ctx.close()
            return

        in_heredoc = shell.heredoc is not None
        if not in_heredoc and text:
            logger.info("Telnet cmd from %s: %r", ctx.addr, text)
            ctx.event("shell_command", service="telnet", command=text[:500])

            hits = classify(text.encode("utf-8", errors="replace"))
            if hits:
                ctx.event("exploit_attempt", command=text[:200],
                          **as_event_fields(hits))

            heredoc = parse_heredoc(text)
            if heredoc is not None:
                shell.heredoc = (heredoc[0], heredoc[1], bytearray())
                await ctx.send(b"> ")
                return

        result = shell.execute(text)

        for name, fields in result.events:
            ctx.event(name, service="telnet", **fields)
        for name, blob in result.artifacts:
            digest = ctx.artifact(name, blob, kind="shell_upload")
            logger.info("Telnet artifact from %s: %s (%d bytes) sha256=%s",
                        ctx.addr, name, len(blob), digest)

        if result.output:
            await ctx.send(result.output)
        if result.close:
            await ctx.send(b"\r\n")
            ctx.close()
            return
        if shell.heredoc is not None:
            await ctx.send(b"> ")
        else:
            await ctx.send(shell.prompt)
