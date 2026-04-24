"""Tests for YaraScanner — tolerate yara-python being absent."""

import sys
import types
from unittest.mock import MagicMock

import pytest

import honeyknot.yara_scan as y
from honeyknot.yara_scan import YaraScanner


class TestYaraScannerNoDep:
    def test_no_rules_path_is_noop(self):
        s = YaraScanner(None)
        assert s.enabled is False
        assert s.scan(b"anything") == []

    def test_missing_yara_module_warns_and_nooops(self, tmp_path, caplog,
                                                   monkeypatch):
        monkeypatch.setattr(y, "yara", None)
        (tmp_path / "x.yar").write_text("rule r { condition: true }")
        with caplog.at_level("WARNING"):
            s = YaraScanner(tmp_path)
        assert s.enabled is False
        assert any("yara-python is not installed" in r.message
                   for r in caplog.records)

    def test_missing_path_logs_error(self, tmp_path, caplog, monkeypatch):
        # Need yara non-None so we don't bail on the import-guard branch
        monkeypatch.setattr(y, "yara", MagicMock())
        missing = tmp_path / "nope"
        with caplog.at_level("ERROR"):
            s = YaraScanner(missing)
        assert s.enabled is False


class TestYaraScannerStubbed:
    @staticmethod
    def _install_stub(monkeypatch):
        """Install a stub `yara` module so we don't need the real dep."""
        stub = types.ModuleType("yara")

        class _Match:
            def __init__(self, rule, tags=None, meta=None, strings=None):
                self.rule = rule
                self.tags = tags or []
                self.meta = meta or {}
                self.strings = strings or []

        class _Rules:
            def __init__(self, matches):
                self._matches = matches

            def match(self, data, timeout=10):
                return list(self._matches)

        def compile(filepath=None, filepaths=None):
            # Return a Rules that fires a single match when data contains "BAD"
            class _Dynamic(_Rules):
                def match(self_inner, data, timeout=10):
                    if b"BAD" in data:
                        return [_Match("bad_rule",
                                       tags=["malware"],
                                       meta={"author": "hk"},
                                       strings=[("offset", "id", b"BAD")])]
                    return []
            return _Dynamic([])

        class SyntaxError(Exception):
            pass

        class Error(Exception):
            pass

        stub.compile = compile
        stub.SyntaxError = SyntaxError
        stub.Error = Error
        monkeypatch.setitem(sys.modules, "yara", stub)
        monkeypatch.setattr(y, "yara", stub)
        return stub

    def test_compiles_directory_and_matches(self, tmp_path, monkeypatch):
        self._install_stub(monkeypatch)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "r.yar").write_text('rule r { strings: $a = "BAD" condition: $a }')
        s = YaraScanner(rules_dir)
        assert s.enabled is True

        matches = s.scan(b"hello BAD world")
        assert len(matches) == 1
        assert matches[0]["rule"] == "bad_rule"
        assert matches[0]["tags"] == ["malware"]
        assert matches[0]["meta"] == {"author": "hk"}
        assert matches[0]["strings"] == 1

    def test_no_matches_returns_empty(self, tmp_path, monkeypatch):
        self._install_stub(monkeypatch)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "r.yar").write_text("rule r { condition: true }")
        s = YaraScanner(rules_dir)
        assert s.scan(b"clean payload") == []

    def test_empty_dir_logs_error(self, tmp_path, monkeypatch, caplog):
        self._install_stub(monkeypatch)
        rules_dir = tmp_path / "empty"
        rules_dir.mkdir()
        with caplog.at_level("ERROR"):
            s = YaraScanner(rules_dir)
        assert s.enabled is False
        assert any("No .yar" in r.message for r in caplog.records)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
