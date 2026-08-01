"""An emulated BusyBox/Linux shell, good enough to make a botnet commit.

Why this exists
---------------
A telnet honeypot that answers every command with a bare `#` prompt gets
credentials and nothing else. IoT malware is *paranoid*: before it spends a
payload it fingerprints the host, and a wrong answer at any step makes the
loader hang up and move on. The sequence a Mirai-class loader runs is well
known and every step is a checkpoint:

  1. `enable`, `system`, `shell`, `sh` — walk out of a restricted CLI.
  2. `/bin/busybox <RANDOM_TOKEN>` — BusyBox answers
     `<TOKEN>: applet not found`. The loader greps for that exact string to
     confirm it is on BusyBox. A generic error, or silence, ends the session.
  3. `cat /proc/mounts` — find a writable filesystem to stage in.
  4. `cat /bin/echo` — read a real binary's ELF header to learn the CPU
     architecture, because the botnet keeps a separate payload per arch.
  5. Only then: `wget`/`tftp`/`echo -ne '\\x7fELF...' >> .s` to deliver.

So the value of this module is entirely in step 5 — but you only get step 5
by passing 1 through 4. That's why the emulator bothers with a virtual
filesystem, a per-architecture ELF header, and BusyBox's exact wording.

What it captures
----------------
`ShellResult.artifacts` carries reconstructed file content back to the
caller, which stores it in the sample store like any other capture. Three
delivery routes land there:

  * `echo -ne '\\x7fELF...' >> dvrHelper` — the echo-loader, used when the
    device has no wget/tftp. The binary is rebuilt byte-for-byte from the
    escape sequences.
  * `cat > /tmp/x << EOF ... EOF` — heredoc script drops.
  * `wget http://.../x -O /tmp/x` — the URL is recorded as an IOC and, if
    the operator enabled payload fetching, retrieved out of band.

Nothing here executes anything. Every command is answered from a table.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

# Cap the reconstructed-file size so an attacker can't echo us to death,
# and the per-session file count for the same reason.
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 32
MAX_OUTPUT_BYTES = 256 * 1024

# arch -> (ELF class, ELF endianness, e_machine, `uname -m`, cpuinfo model)
_ARCH_TABLE: dict[str, tuple[int, int, int, str, str]] = {
    "x86_64": (2, 1, 0x3E, "x86_64", "Intel(R) Xeon(R) CPU E5-2680 v3 @ 2.50GHz"),
    "i686":   (1, 1, 0x03, "i686", "Intel(R) Atom(TM) CPU D525 @ 1.80GHz"),
    "arm":    (1, 1, 0x28, "armv7l", "ARMv7 Processor rev 5 (v7l)"),
    "arm64":  (2, 1, 0xB7, "aarch64", "Cortex-A53"),
    "mips":   (1, 2, 0x08, "mips", "MIPS 24Kc V7.4"),
    "mipsel": (1, 1, 0x08, "mips", "MIPS 24Kc V7.4"),
    "ppc":    (1, 2, 0x14, "ppc", "PPC 405GP"),
    "sh4":    (1, 1, 0x2A, "sh4", "SH-4 rev 1.0"),
    "m68k":   (1, 2, 0x04, "m68k", "Motorola 68020"),
    "sparc":  (1, 2, 0x02, "sparc", "TI UltraSparc IIi (Sabre)"),
}

BUSYBOX_APPLETS = (
    "[, [[, ash, awk, base64, basename, cat, chgrp, chmod, chown, chroot, "
    "cp, crond, cut, date, dd, df, dirname, dmesg, du, echo, egrep, env, "
    "expr, false, fgrep, find, free, grep, gunzip, gzip, halt, head, "
    "hexdump, hostname, id, ifconfig, init, insmod, kill, killall, ln, "
    "login, ls, lsmod, md5sum, mkdir, mknod, more, mount, mv, nc, netstat, "
    "nslookup, ntpd, passwd, ping, ps, pwd, reboot, rm, rmdir, route, sed, "
    "seq, sh, sleep, sort, strings, sync, tail, tar, telnetd, tftp, time, "
    "top, touch, tr, true, umount, uname, uniq, uptime, vi, wc, wget, "
    "which, whoami, xargs, yes, zcat"
)

# `\xNN`, `\NNN` (octal), and the usual C escapes, as emitted by echo -ne.
_ESCAPE_RE = re.compile(rb"\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|[abefnrtv\\0])")
_ESCAPE_MAP = {
    b"a": b"\a", b"b": b"\b", b"e": b"\x1b", b"f": b"\f",
    b"n": b"\n", b"r": b"\r", b"t": b"\t", b"v": b"\v",
    b"\\": b"\\", b"0": b"\x00",
}


@dataclass
class ShellResult:
    """What the transport should do with one executed line.

    `output` goes to the wire before the next prompt. `events` are
    `(name, fields)` pairs for `ctx.event`. `artifacts` are
    `(filename, content)` pairs the caller should hand to the sample store.
    """
    output: bytes = b""
    close: bool = False
    events: list[tuple[str, dict]] = field(default_factory=list)
    artifacts: list[tuple[str, bytes]] = field(default_factory=list)


class ShellSession:
    """Per-connection emulated shell state.

    Lives on `ctx.state`, never on a handler instance — one of these per
    connection. It owns the virtual cwd, environment, and the files the
    attacker believes they have written.
    """

    def __init__(self, hostname: str = "localhost", user: str = "root",
                 arch: str = "x86_64", opts: dict | None = None):
        opts = opts or {}
        self.hostname = hostname
        self.user = user
        self.arch = arch if arch in _ARCH_TABLE else "x86_64"
        self.kernel = opts.get("kernel", "3.10.14")
        self.distro = opts.get("distro", "Linux")
        self.cwd = "/"
        self.files: dict[str, bytearray] = {}
        self.heredoc: tuple[str, str, bytearray] | None = None
        self.pending_binary_write: str | None = None
        self.command_count = 0

    # -- prompt ------------------------------------------------------------

    @property
    def prompt(self) -> bytes:
        sigil = "#" if self.user == "root" else "$"
        return f"{self.user}@{self.hostname}:{self._short_cwd()}{sigil} ".encode()

    def _short_cwd(self) -> str:
        if self.cwd == f"/{self.user}" or self.cwd == "/root":
            return "~"
        return self.cwd

    # -- entry point -------------------------------------------------------

    def execute(self, line: str) -> ShellResult:
        """Run one input line and return everything the caller needs.

        Handles an in-progress heredoc, then splits the line on `;`, `&&`,
        `||`, and `|` and runs each segment. A pipeline's left-hand output is
        fed to the right-hand command only for the filters we emulate; for
        `| sh` it is treated as "execute what you just downloaded", which is
        an event worth its own name.
        """
        result = ShellResult()

        if self.heredoc is not None:
            self._feed_heredoc(line, result)
            return result

        self.command_count += 1
        segments = _split_chain(line)
        piped_input: bytes | None = None

        for idx, (op, raw) in enumerate(segments):
            text = raw.strip()
            if not text:
                continue
            stdin = piped_input if op == "|" else None
            seg = self._run_one(text, result, stdin=stdin)
            # Only a pipe forwards output downstream; `;` / `&&` / `||` emit it.
            if idx + 1 < len(segments) and segments[idx + 1][0] == "|":
                piped_input = seg
            else:
                piped_input = None
                result.output += seg
            if result.close:
                break
            if len(result.output) > MAX_OUTPUT_BYTES:
                result.output = result.output[:MAX_OUTPUT_BYTES]
                break

        return result

    # -- dispatch ----------------------------------------------------------

    def _run_one(self, text: str, result: ShellResult,
                 stdin: bytes | None = None) -> bytes:
        try:
            tokens = shlex.split(text, posix=True)
        except ValueError:
            # Unbalanced quote — a real shell would prompt for more input;
            # attackers send it by accident constantly. Degrade to a split.
            tokens = text.split()
        if not tokens:
            return b""

        tokens, redirect = _extract_redirect(tokens)
        if not tokens:
            return b""

        argv0 = tokens[0]
        cmd = argv0.rsplit("/", 1)[-1]
        args = tokens[1:]

        # `/bin/busybox CMD ...` — dispatch the applet, but remember we were
        # invoked through busybox so an unknown applet gets busybox's wording.
        via_busybox = cmd == "busybox"
        if via_busybox:
            if not args:
                return f"BusyBox v1.20.2 (2016-05-13) multi-call binary.\r\n\r\n" \
                       f"Currently defined functions:\r\n{BUSYBOX_APPLETS}\r\n".encode()
            applet = args[0]
            # This is the fingerprint check. BusyBox prints exactly this and
            # loaders grep for "applet not found".
            if not _is_known_applet(applet):
                result.events.append(
                    ("busybox_probe", {"applet": applet}))
                return f"{applet}: applet not found\r\n".encode()
            cmd = applet
            args = args[1:]

        handler = _COMMANDS.get(cmd)
        if handler is None:
            if _looks_like_path(argv0):
                # `./x86` / `/tmp/.s` — they are running their dropped payload.
                resolved = self._abspath(argv0.removeprefix("./"))
                known = resolved in self.files or argv0 in self.files
                result.events.append(("payload_exec", {
                    "path": argv0, "resolved": resolved,
                    "staged": known, "argv": tokens[:8],
                }))
                # A staged file "runs" silently, like a real daemonizing bot.
                # An unstaged one gets the shell's real error, which is what
                # tells the loader to fall back to another delivery method —
                # and that fallback is another payload for us.
                if known:
                    return b""
                return f"-sh: {argv0}: not found\r\n".encode()
            return f"-sh: {cmd}: command not found\r\n".encode()

        out = handler(self, args, result, stdin)

        if redirect is not None:
            mode, path = redirect
            self._write_file(path, out, append=(mode == ">>"), result=result)
            return b""
        return out

    # -- virtual filesystem writes ----------------------------------------

    def _write_file(self, path: str, data: bytes, *, append: bool,
                    result: ShellResult) -> None:
        path = self._abspath(path)
        buf = self.files.get(path)
        if buf is None:
            if len(self.files) >= MAX_FILES:
                return
            buf = bytearray()
            self.files[path] = buf
        if not append:
            buf.clear()
        room = MAX_FILE_BYTES - len(buf)
        if room > 0:
            buf.extend(data[:room])

        result.events.append(("file_write", {
            "path": path, "bytes": len(data), "total": len(buf),
            "append": append,
        }))
        # An echo-loader writes in many small appends; only surface the file
        # as an artifact once it looks like a complete binary or script.
        if _looks_like_artifact(buf):
            result.artifacts.append((path, bytes(buf)))

    def _feed_heredoc(self, line: str, result: ShellResult) -> None:
        assert self.heredoc is not None
        path, terminator, buf = self.heredoc
        if line.strip() == terminator:
            self.heredoc = None
            self._write_file(path, bytes(buf), append=False, result=result)
            if bytes(buf):
                result.artifacts.append((self._abspath(path), bytes(buf)))
            return
        if len(buf) < MAX_FILE_BYTES:
            buf.extend(line.encode("utf-8", errors="replace") + b"\n")

    def _abspath(self, path: str) -> str:
        if path.startswith("/"):
            return path
        base = self.cwd.rstrip("/")
        return f"{base}/{path}"

    # -- arch-derived content ---------------------------------------------

    def elf_header(self) -> bytes:
        """A believable ELF header for this session's architecture.

        Loaders read the first ~20 bytes of a known-present binary to choose
        which payload to send. Getting `e_machine` right is the difference
        between collecting a MIPS sample and collecting nothing.
        """
        elf_class, endian, machine, _, _ = _ARCH_TABLE[self.arch]
        ident = bytes([0x7F, 0x45, 0x4C, 0x46, elf_class, endian, 1]) + bytes(9)
        order = "big" if endian == 2 else "little"
        body = (2).to_bytes(2, order)            # e_type = ET_EXEC
        body += machine.to_bytes(2, order)       # e_machine
        body += (1).to_bytes(4, order)           # e_version
        # Entry point / offsets: plausible constants, never parsed by loaders.
        width = 8 if elf_class == 2 else 4
        body += (0x400440).to_bytes(width, order)
        body += (64 if elf_class == 2 else 52).to_bytes(width, order)
        body += (0x1A48).to_bytes(width, order)
        return ident + body + bytes(24)

    def uname_m(self) -> str:
        return _ARCH_TABLE[self.arch][3]

    def cpu_model(self) -> str:
        return _ARCH_TABLE[self.arch][4]


# --------------------------------------------------------------------------
# Command implementations. Signature: (session, args, result, stdin) -> bytes
# --------------------------------------------------------------------------

def _c_echo(s: ShellSession, args, result, stdin) -> bytes:
    interpret = False
    trailing_nl = True
    idx = 0
    while idx < len(args) and args[idx].startswith("-") and len(args[idx]) > 1:
        flags = args[idx][1:]
        if not set(flags) <= {"e", "n", "E"}:
            break
        if "e" in flags:
            interpret = True
        if "n" in flags:
            trailing_nl = False
        idx += 1
    text = " ".join(args[idx:]).encode("utf-8", errors="replace")
    if interpret:
        text = _unescape(text)
    return text + (b"\r\n" if trailing_nl else b"")


def _c_cat(s: ShellSession, args, result, stdin) -> bytes:
    # `cat > file << EOF` is parsed before we get here; a bare `cat` with a
    # heredoc marker still reaches us as arguments.
    files = [a for a in args if not a.startswith("-")]
    if not files:
        return stdin or b""
    out = bytearray()
    for name in files:
        path = s._abspath(name)
        if path in s.files:
            out.extend(s.files[path])
            continue
        content = _virtual_file(s, path)
        if content is None:
            out.extend(f"cat: {name}: No such file or directory\r\n".encode())
        else:
            out.extend(content)
    return bytes(out)


def _c_uname(s: ShellSession, args, result, stdin) -> bytes:
    flags = "".join(a[1:] for a in args if a.startswith("-"))
    machine = s.uname_m()
    if "a" in flags:
        return (f"Linux {s.hostname} {s.kernel} #1 SMP Mon Jan 6 12:00:00 UTC 2020 "
                f"{machine} GNU/Linux\r\n").encode()
    if "m" in flags:
        return f"{machine}\r\n".encode()
    if "r" in flags:
        return f"{s.kernel}\r\n".encode()
    if "n" in flags:
        return f"{s.hostname}\r\n".encode()
    return b"Linux\r\n"


def _c_id(s: ShellSession, args, result, stdin) -> bytes:
    if s.user == "root":
        return b"uid=0(root) gid=0(root) groups=0(root)\r\n"
    return f"uid=1000({s.user}) gid=1000({s.user}) groups=1000({s.user})\r\n".encode()


def _c_whoami(s: ShellSession, args, result, stdin) -> bytes:
    return f"{s.user}\r\n".encode()


def _c_pwd(s: ShellSession, args, result, stdin) -> bytes:
    return f"{s.cwd}\r\n".encode()


def _c_cd(s: ShellSession, args, result, stdin) -> bytes:
    target = args[0] if args else "/"
    if target == "..":
        s.cwd = "/" + "/".join(s.cwd.strip("/").split("/")[:-1])
        s.cwd = s.cwd if s.cwd != "" else "/"
    elif target == "~":
        s.cwd = "/root" if s.user == "root" else f"/home/{s.user}"
    else:
        s.cwd = s._abspath(target).replace("//", "/")
    # A loader `cd`s through candidate staging dirs looking for one that
    # doesn't error; always succeeding is what we want.
    return b""


def _c_ls(s: ShellSession, args, result, stdin) -> bytes:
    long_form = any(a.startswith("-") and "l" in a for a in args)
    targets = [a for a in args if not a.startswith("-")]
    path = s._abspath(targets[0]) if targets else s.cwd
    names = list(_DIRS.get(path.rstrip("/") or "/", ()))
    for f in s.files:
        parent = f.rsplit("/", 1)[0] or "/"
        if parent == (path.rstrip("/") or "/"):
            names.append(f.rsplit("/", 1)[-1])
    if not names:
        return b""
    if not long_form:
        return ("  ".join(sorted(names)) + "\r\n").encode()
    lines = ["total 44"]
    for n in sorted(names):
        lines.append(f"-rwxr-xr-x    1 root     root         12345 Jan  6 12:00 {n}")
    return ("\r\n".join(lines) + "\r\n").encode()


def _downloader(tool: str):
    """Build a wget/curl-style handler that records the URL and fakes success.

    The URL is the whole point of the session, so it gets its own event even
    when the invocation is malformed — a botnet with a broken command line
    still tells us where its payload lives.
    """
    def run(s: ShellSession, args, result, stdin) -> bytes:
        urls = [a for a in args
                if a.startswith(("http://", "https://", "ftp://"))]
        out_name = None
        for i, a in enumerate(args):
            if a in ("-O", "-o", "--output-document", "--output") \
                    and i + 1 < len(args):
                out_name = args[i + 1]
        # A bare host argument only counts when there's no URL — otherwise
        # `-O dvrHelper` gets mistaken for the server.
        skip = set()
        for i, a in enumerate(args):
            if a.startswith("-"):
                skip.add(i)
                if a in ("-O", "-o", "--output-document", "--output", "-U",
                         "--user-agent", "-H") and i + 1 < len(args):
                    skip.add(i + 1)
        host = _url_host(urls[0]) if urls else next(
            (a for i, a in enumerate(args) if i not in skip), None)

        result.events.append(("download_attempt", {
            "tool": tool, "urls": urls, "host": host, "output": out_name,
            "argv": args[:12],
        }))
        if not urls:
            return b""
        # curl writes the body to stdout and is usually invoked with -s;
        # wget prints a progress block. Matching each tool's real output
        # matters when the next command in the chain greps for it.
        if tool == "curl":
            return b""
        name = out_name or urls[0].rsplit("/", 1)[-1] or "index.html"
        return (f"Connecting to {_url_host(urls[0])}... connected.\r\n"
                f"HTTP request sent, awaiting response... 200 OK\r\n"
                f"Length: 108492 (106K) [application/octet-stream]\r\n"
                f"Saving to: '{name}'\r\n\r\n"
                f"{name}          100%[=================>] 105.95K  --.-KB/s"
                f"    in 0.1s\r\n\r\n"
                f"'{name}' saved [108492/108492]\r\n").encode()
    return run


def _c_tftp(s: ShellSession, args, result, stdin) -> bytes:
    # Only -r/-l/-c take a filename; -g/-p are direction flags, so consuming
    # their "argument" would swallow the server address.
    takes_arg = ("-r", "-l", "-c")
    remote = None
    consumed: set[int] = set()
    for i, a in enumerate(args):
        if a in takes_arg and i + 1 < len(args):
            remote = args[i + 1]
            consumed.add(i + 1)
    host = next((a for i, a in enumerate(args)
                 if not a.startswith("-") and i not in consumed), None)
    result.events.append(("download_attempt", {
        "tool": "tftp", "host": host, "remote": remote, "argv": args[:12],
    }))
    return b""


def _c_chmod(s: ShellSession, args, result, stdin) -> bytes:
    targets = [a for a in args if not a.startswith("-") and
               not re.fullmatch(r"[0-7]{3,4}|[ugoa]*[+-][rwxst]+", a)]
    if targets:
        result.events.append(("chmod", {"targets": targets[:8], "argv": args[:8]}))
    return b""


def _c_rm(s: ShellSession, args, result, stdin) -> bytes:
    for a in args:
        if not a.startswith("-"):
            s.files.pop(s._abspath(a), None)
    result.events.append(("file_delete", {"argv": args[:8]}))
    return b""


def _c_ps(s: ShellSession, args, result, stdin) -> bytes:
    return (
        "  PID USER       VSZ STAT COMMAND\r\n"
        "    1 root      2200 S    /sbin/init\r\n"
        "  102 root         0 SW   [kworker/0:1]\r\n"
        "  418 root      1868 S    /sbin/syslogd -n\r\n"
        "  531 root      2064 S    /usr/sbin/sshd -D\r\n"
        "  604 root      1892 S    /sbin/telnetd -F\r\n"
        f"  911 {s.user:<8} 2196 R    ps\r\n"
    ).encode()


def _c_free(s: ShellSession, args, result, stdin) -> bytes:
    return (
        b"             total       used       free     shared    buffers\r\n"
        b"Mem:        246220     198364      47856          0      12844\r\n"
        b"-/+ buffers/cache:     185520      60700\r\n"
        b"Swap:            0          0          0\r\n"
    )


def _c_df(s: ShellSession, args, result, stdin) -> bytes:
    return (
        b"Filesystem           1K-blocks      Used Available Use% Mounted on\r\n"
        b"/dev/root                29876     26412      1924  93% /\r\n"
        b"tmpfs                   123108         0    123108   0% /dev/shm\r\n"
        b"tmpfs                   123108        84    123024   1% /tmp\r\n"
        b"tmpfs                   123108        16    123092   1% /var\r\n"
    )


def _c_mount(s: ShellSession, args, result, stdin) -> bytes:
    return _MOUNTS.replace(b"\n", b"\r\n")


def _c_netstat(s: ShellSession, args, result, stdin) -> bytes:
    return (
        b"Active Internet connections (servers and established)\r\n"
        b"Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
        b"tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN\r\n"
        b"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
        b"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
    )


def _c_ifconfig(s: ShellSession, args, result, stdin) -> bytes:
    return (
        b"eth0      Link encap:Ethernet  HWaddr 00:1A:2B:3C:4D:5E\r\n"
        b"          inet addr:192.168.1.42  Bcast:192.168.1.255  Mask:255.255.255.0\r\n"
        b"          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n"
        b"          RX packets:184213 errors:0 dropped:0 overruns:0 frame:0\r\n"
        b"          TX packets:97431 errors:0 dropped:0 overruns:0 carrier:0\r\n"
        b"\r\n"
        b"lo        Link encap:Local Loopback\r\n"
        b"          inet addr:127.0.0.1  Mask:255.0.0.0\r\n"
        b"          UP LOOPBACK RUNNING  MTU:65536  Metric:1\r\n"
    )


def _c_nproc(s: ShellSession, args, result, stdin) -> bytes:
    return b"2\r\n"


def _c_uptime(s: ShellSession, args, result, stdin) -> bytes:
    return b" 12:04:31 up 47 days,  3:11,  1 user,  load average: 0.08, 0.03, 0.05\r\n"


def _c_crontab(s: ShellSession, args, result, stdin) -> bytes:
    if any(a == "-l" for a in args):
        return b"no crontab for root\r\n"
    result.events.append(("crontab", {"argv": args[:8]}))
    return b""


def _c_which(s: ShellSession, args, result, stdin) -> bytes:
    out = bytearray()
    for a in args:
        if a in _COMMANDS or _is_known_applet(a):
            out.extend(f"/bin/{a}\r\n".encode())
    return bytes(out)


def _c_grep(s: ShellSession, args, result, stdin) -> bytes:
    if stdin is None:
        return b""
    patterns = [a for a in args if not a.startswith("-")]
    if not patterns:
        return b""
    needle = patterns[0].encode("utf-8", errors="replace")
    return b"\r\n".join(
        line for line in stdin.replace(b"\r\n", b"\n").split(b"\n")
        if needle.lower() in line.lower()
    ) + b"\r\n"


def _c_head_tail(s: ShellSession, args, result, stdin) -> bytes:
    data = stdin if stdin is not None else _c_cat(s, args, result, None)
    lines = data.replace(b"\r\n", b"\n").split(b"\n")
    return b"\r\n".join(lines[:10]) + b"\r\n"


def _c_wc(s: ShellSession, args, result, stdin) -> bytes:
    data = stdin or b""
    return f"      {data.count(chr(10).encode())}      "\
           f"{len(data.split())}      {len(data)}\r\n".encode()


def _c_dd(s: ShellSession, args, result, stdin) -> bytes:
    # Mirai's echo-loader verifies its staged file with
    # `dd bs=52 count=1 if=.s || cat .s`. Answering plausibly keeps it going.
    src = None
    for a in args:
        if a.startswith("if="):
            src = a[3:]
    if src:
        path = s._abspath(src)
        blob = s.files.get(path) or _virtual_file(s, path) or b""
        return bytes(blob[:512])
    return b"0+0 records in\r\n0+0 records out\r\n"


def _c_pipe_to_shell(s: ShellSession, args, result, stdin) -> bytes:
    """`sh` / `bash` as a pipeline sink — i.e. `curl ... | sh`."""
    if stdin:
        result.events.append(("script_exec", {
            "bytes": len(stdin),
            "preview": stdin[:200].decode("utf-8", errors="replace"),
        }))
        result.artifacts.append(("piped-script.sh", stdin))
    return b""


def _c_exit(s: ShellSession, args, result, stdin) -> bytes:
    result.close = True
    return b""


def _c_noop(s: ShellSession, args, result, stdin) -> bytes:
    return b""


def _c_ok(s: ShellSession, args, result, stdin) -> bytes:
    return b"OK\r\n"


def _c_hostname(s: ShellSession, args, result, stdin) -> bytes:
    return f"{s.hostname}\r\n".encode()


def _c_date(s: ShellSession, args, result, stdin) -> bytes:
    # Deliberately fixed: a honeypot that reports a clock skewed from its own
    # TCP timestamps is a tell, and nothing in a loader parses this.
    return b"Mon Jan  6 12:04:31 UTC 2020\r\n"


def _c_mkdir(s: ShellSession, args, result, stdin) -> bytes:
    return b""


def _c_touch(s: ShellSession, args, result, stdin) -> bytes:
    for a in args:
        if not a.startswith("-"):
            s.files.setdefault(s._abspath(a), bytearray())
    return b""


def _c_cp_mv(s: ShellSession, args, result, stdin) -> bytes:
    plain = [a for a in args if not a.startswith("-")]
    if len(plain) >= 2:
        src, dst = s._abspath(plain[0]), s._abspath(plain[1])
        blob = s.files.get(src)
        if blob is not None and len(s.files) < MAX_FILES:
            s.files[dst] = bytearray(blob)
        result.events.append(("file_copy", {"src": plain[0], "dst": plain[1]}))
    return b""


def _c_kill(s: ShellSession, args, result, stdin) -> bytes:
    # Coin miners and IoT bots kill competitors on the way in; the target
    # list is a good family fingerprint.
    result.events.append(("process_kill", {"argv": args[:12]}))
    return b""


def _c_pkgmgr(s: ShellSession, args, result, stdin) -> bytes:
    result.events.append(("package_install", {"argv": args[:12]}))
    return b"Reading package lists... Done\r\n"


_COMMANDS = {
    "echo": _c_echo, "cat": _c_cat, "uname": _c_uname, "id": _c_id,
    "whoami": _c_whoami, "pwd": _c_pwd, "cd": _c_cd, "ls": _c_ls,
    "dir": _c_ls, "wget": _downloader("wget"), "curl": _downloader("curl"),
    "ftpget": _downloader("ftpget"), "tftp": _c_tftp, "chmod": _c_chmod,
    "chown": _c_noop, "rm": _c_rm, "ps": _c_ps, "top": _c_ps,
    "free": _c_free, "df": _c_df, "mount": _c_mount, "netstat": _c_netstat,
    "ss": _c_netstat, "ifconfig": _c_ifconfig, "ip": _c_ifconfig,
    "nproc": _c_nproc, "uptime": _c_uptime, "w": _c_uptime,
    "crontab": _c_crontab, "which": _c_which, "whereis": _c_which,
    "grep": _c_grep, "egrep": _c_grep, "fgrep": _c_grep,
    "head": _c_head_tail, "tail": _c_head_tail, "wc": _c_wc, "dd": _c_dd,
    "sh": _c_pipe_to_shell, "bash": _c_pipe_to_shell, "ash": _c_pipe_to_shell,
    "exit": _c_exit, "quit": _c_exit, "logout": _c_exit,
    "hostname": _c_hostname, "date": _c_date, "mkdir": _c_mkdir,
    "touch": _c_touch, "cp": _c_cp_mv, "mv": _c_cp_mv,
    "kill": _c_kill, "killall": _c_kill, "pkill": _c_kill,
    "apt-get": _c_pkgmgr, "apt": _c_pkgmgr, "yum": _c_pkgmgr,
    "apk": _c_pkgmgr, "opkg": _c_pkgmgr,
    # Restricted-CLI escapes. Mirai sends these blind; any output other than
    # an error is treated as success.
    "enable": _c_noop, "system": _c_noop, "shell": _c_noop, "linuxshell": _c_noop,
    "sleep": _c_noop, "export": _c_noop, "unset": _c_noop, "set": _c_noop,
    "history": _c_noop, "clear": _c_noop, "sync": _c_noop, "true": _c_noop,
    "nohup": _c_noop, "setsid": _c_noop, "service": _c_ok, "systemctl": _c_ok,
    "lscpu": lambda s, a, r, i: _virtual_file(s, "/proc/cpuinfo") or b"",
    "reboot": _c_noop, "halt": _c_noop, "poweroff": _c_noop,
}


# --------------------------------------------------------------------------
# Virtual filesystem content
# --------------------------------------------------------------------------

_MOUNTS = (
    b"rootfs / rootfs rw 0 0\n"
    b"/dev/root / squashfs ro,relatime 0 0\n"
    b"proc /proc proc rw,relatime 0 0\n"
    b"sysfs /sys sysfs rw,relatime 0 0\n"
    b"tmpfs /tmp tmpfs rw,relatime 0 0\n"
    b"tmpfs /var tmpfs rw,relatime 0 0\n"
    b"tmpfs /dev tmpfs rw,relatime,size=8192k 0 0\n"
    b"devpts /dev/pts devpts rw,relatime,mode=600 0 0\n"
)

_PASSWD = (
    b"root:x:0:0:root:/root:/bin/sh\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/bin/false\n"
    b"bin:x:2:2:bin:/bin:/bin/false\n"
    b"sys:x:3:3:sys:/dev:/bin/false\n"
    b"nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"
    b"sshd:x:22:22:sshd:/var/run/sshd:/bin/false\n"
    b"admin:x:1000:1000:admin:/home/admin:/bin/sh\n"
)

# Deliberately hash-shaped but not a real hash of anything. If these strings
# ever show up in a paste dump or a credential-stuffing list, that's proof of
# provenance: they came from this honeypot and nowhere else.
_SHADOW = (
    b"root:$1$hk9Qz2Vt$0000honeyknotcanary0:18000:0:99999:7:::\n"
    b"daemon:*:18000:0:99999:7:::\n"
    b"admin:$1$hk9Qz2Vt$1111honeyknotcanary1:18000:0:99999:7:::\n"
)

_DIRS: dict[str, tuple[str, ...]] = {
    "/": ("bin", "dev", "etc", "lib", "mnt", "proc", "root", "sbin",
          "sys", "tmp", "usr", "var"),
    "/bin": ("busybox", "sh", "cat", "echo", "ls", "ps", "chmod", "wget"),
    "/tmp": (),
    "/var": ("log", "run", "tmp"),
    "/dev": ("null", "zero", "tty", "watchdog", "shm"),
    "/etc": ("passwd", "shadow", "hosts", "resolv.conf", "inittab"),
    "/root": (".bash_history", ".profile"),
    "/proc": ("cpuinfo", "meminfo", "mounts", "net", "version", "self"),
}


def _virtual_file(s: ShellSession, path: str) -> bytes | None:
    """Content for a path in the fake filesystem, or None for ENOENT."""
    path = path.rstrip("/") or "/"

    if path == "/proc/mounts" or path == "/etc/mtab":
        return _MOUNTS.replace(b"\n", b"\r\n")
    if path == "/etc/passwd":
        return _PASSWD.replace(b"\n", b"\r\n")
    if path == "/etc/shadow":
        return _SHADOW.replace(b"\n", b"\r\n")
    if path == "/proc/version":
        return (f"Linux version {s.kernel} (buildroot@builder) "
                f"(gcc version 4.8.5) #1 SMP Mon Jan 6 12:00:00 UTC 2020\r\n"
                ).encode()
    if path == "/proc/cpuinfo":
        model = s.cpu_model()
        if s.arch.startswith("mips"):
            return (f"system type\t\t: Ralink SoC\r\n"
                    f"processor\t\t: 0\r\ncpu model\t\t: {model}\r\n"
                    f"BogoMIPS\t\t: 386.04\r\n").encode()
        return (f"processor\t: 0\r\nmodel name\t: {model}\r\n"
                f"cpu MHz\t\t: 2500.000\r\nbogomips\t: 5000.00\r\n\r\n"
                f"processor\t: 1\r\nmodel name\t: {model}\r\n"
                f"cpu MHz\t\t: 2500.000\r\nbogomips\t: 5000.00\r\n").encode()
    if path == "/proc/meminfo":
        return (b"MemTotal:         246220 kB\r\nMemFree:           47856 kB\r\n"
                b"MemAvailable:      60700 kB\r\nBuffers:           12844 kB\r\n")
    if path == "/proc/net/tcp":
        return (b"  sl  local_address rem_address   st tx_queue rx_queue\r\n"
                b"   0: 00000000:0017 00000000:0000 0A 00000000:00000000\r\n"
                b"   1: 00000000:0050 00000000:0000 0A 00000000:00000000\r\n")
    if path in ("/etc/resolv.conf",):
        return b"nameserver 8.8.8.8\r\nnameserver 1.1.1.1\r\n"
    if path == "/etc/hosts":
        return f"127.0.0.1\tlocalhost\r\n127.0.1.1\t{s.hostname}\r\n".encode()
    if path in ("/root/.bash_history", "/home/admin/.bash_history"):
        return b""
    # Any binary under /bin, /sbin, /usr/bin gets a real-looking ELF header.
    # This is the architecture-detection step; see ShellSession.elf_header.
    if path.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")):
        return s.elf_header() + b"\x00" * 32
    return None


# --------------------------------------------------------------------------
# Line parsing helpers
# --------------------------------------------------------------------------

def _split_chain(line: str) -> list[tuple[str, str]]:
    """Split a command line on `;`, `&&`, `||`, `|`, honoring quotes.

    Returns `[(operator_before_segment, segment_text), ...]`; the first
    operator is always `""`.
    """
    segments: list[tuple[str, str]] = []
    current = []
    op = ""
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            current.append(ch)
            if ch == quote and (i == 0 or line[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            current.append(ch)
            i += 1
            continue
        two = line[i:i + 2]
        if two in ("&&", "||"):
            segments.append((op, "".join(current)))
            op = two
            current = []
            i += 2
            continue
        if ch in ";|&\n":
            segments.append((op, "".join(current)))
            op = "|" if ch == "|" else ";"
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    segments.append((op, "".join(current)))
    return [(o, t) for o, t in segments if t.strip() or o]


def _extract_redirect(tokens: list[str]) -> tuple[list[str], tuple[str, str] | None]:
    """Pull a `> file` / `>> file` redirect out of a token list."""
    out: list[str] = []
    redirect: tuple[str, str] | None = None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in (">", ">>"):
            if i + 1 < len(tokens):
                redirect = (tok, tokens[i + 1])
                i += 2
                continue
            i += 1
            continue
        if tok.startswith(">>") and len(tok) > 2:
            redirect = (">>", tok[2:])
            i += 1
            continue
        if tok.startswith(">") and len(tok) > 1:
            redirect = (">", tok[1:])
            i += 1
            continue
        out.append(tok)
        i += 1
    return out, redirect


def _unescape(data: bytes) -> bytes:
    """Decode `echo -e` escapes, including the `\\xNN` form loaders use."""
    def repl(m: re.Match) -> bytes:
        seq = m.group(1)
        if seq[:1] in (b"x", b"X"):
            return bytes([int(seq[1:], 16)])
        if seq in _ESCAPE_MAP:
            return _ESCAPE_MAP[seq]
        try:
            return bytes([int(seq, 8) & 0xFF])
        except ValueError:
            return m.group(0)
    return _ESCAPE_RE.sub(repl, data)


def _is_known_applet(name: str) -> bool:
    return name in _COMMANDS or name in {
        a.strip() for a in BUSYBOX_APPLETS.split(",")
    }


def _looks_like_path(argv0: str) -> bool:
    return argv0.startswith(("./", "/", "../")) or "/" in argv0


def _looks_like_artifact(buf: bytearray) -> bool:
    """Is this reconstructed file worth storing as a sample yet?

    ELF and script magic are the two shapes that matter; anything else has
    to reach a size where it's clearly not a config tweak.
    """
    if len(buf) < 4:
        return False
    head = bytes(buf[:4])
    if head == b"\x7fELF":
        return len(buf) >= 64
    if head[:2] in (b"#!", b"MZ"):
        return len(buf) >= 32
    return len(buf) >= 1024


def _url_host(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0]


def parse_heredoc(line: str) -> tuple[str, str] | None:
    """Detect `cat > PATH << TERM` and return `(path, terminator)`.

    Called by the transport before `execute` so the following lines can be
    routed into the heredoc body instead of being run as commands.
    """
    m = re.search(r"cat\s*>\s*(\S+)\s*<<-?\s*['\"]?(\w+)['\"]?", line)
    if m:
        return m.group(1), m.group(2)
    return None
