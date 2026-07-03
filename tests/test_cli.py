"""Tests for the CLI argument surface (--version / --list-protocols)."""

import sys

import pytest

from honeyknot import __version__, cli


def test_version_flag_prints_and_exits(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["honeyknot", "--version"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out


def test_list_protocols_flag(capsys, monkeypatch):
    # Works even though -i/--bind-ip is normally required: the action fires
    # during parsing, before the required-argument check.
    monkeypatch.setattr(sys, "argv", ["honeyknot", "--list-protocols"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "TCP" in out
    assert "UDP" in out
    assert "ssh" in out
    assert "dns" in out


def test_missing_bind_ip_errors(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["honeyknot"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    # argparse exits 2 on a missing required argument.
    assert exc.value.code == 2
