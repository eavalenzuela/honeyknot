"""Tests for honeyknot.config — TOML loading and validation."""

import re
from pathlib import Path

import pytest

from honeyknot.config import load_all_handlers, load_handler

HANDLERS_DIR = Path(__file__).resolve().parent.parent / "handlers"


class TestLoadHandler:
    def test_load_http_handler(self):
        config = load_handler(HANDLERS_DIR / "http_80.toml")
        assert config.port == 80
        assert config.service_type == "http"
        assert len(config.rules) == 4
        assert config.response_headers is not None
        assert config.response_headers.status_line == "HTTP/1.1 200 OK"
        assert config.default_response != ""

    def test_load_tcp_handler(self):
        config = load_handler(HANDLERS_DIR / "ssh_222.toml")
        assert config.port == 222
        assert config.service_type == "tcp"
        assert len(config.rules) == 1
        assert config.response_headers is None

    def test_rules_have_compiled_patterns(self):
        config = load_handler(HANDLERS_DIR / "http_80.toml")
        for rule in config.rules:
            assert isinstance(rule.pattern, re.Pattern)

    def test_rules_have_names(self):
        config = load_handler(HANDLERS_DIR / "http_80.toml")
        names = [r.name for r in config.rules]
        assert "php_request" in names
        assert "root_get" in names

    def test_missing_service_section(self, tmp_path):
        bad = tmp_path / "bad.toml"
        bad.write_text('[[rules]]\npattern = ".*"\nresponse = "hi"\n')
        with pytest.raises(ValueError, match="missing \\[service\\] section"):
            load_handler(bad)

    def test_missing_port(self, tmp_path):
        bad = tmp_path / "bad.toml"
        bad.write_text('[service]\ntype = "tcp"\n')
        with pytest.raises(ValueError, match="missing service.port"):
            load_handler(bad)

    def test_invalid_service_type(self, tmp_path):
        bad = tmp_path / "bad.toml"
        bad.write_text('[service]\nport = 99\ntype = "udp"\n')
        with pytest.raises(ValueError, match="invalid service.type"):
            load_handler(bad)

    def test_invalid_regex_caught_at_load(self, tmp_path):
        bad = tmp_path / "bad.toml"
        bad.write_text(
            '[service]\nport = 99\ntype = "tcp"\n'
            '[[rules]]\nname = "broken"\npattern = "[unclosed"\nresponse = "x"\n'
        )
        with pytest.raises(ValueError, match="invalid regex"):
            load_handler(bad)

    def test_missing_rule_pattern(self, tmp_path):
        bad = tmp_path / "bad.toml"
        bad.write_text(
            '[service]\nport = 99\ntype = "tcp"\n'
            '[[rules]]\nresponse = "x"\n'
        )
        with pytest.raises(ValueError, match="missing 'pattern'"):
            load_handler(bad)

    def test_missing_rule_response(self, tmp_path):
        bad = tmp_path / "bad.toml"
        bad.write_text(
            '[service]\nport = 99\ntype = "tcp"\n'
            '[[rules]]\npattern = ".*"\n'
        )
        with pytest.raises(ValueError, match="missing 'response'"):
            load_handler(bad)

    def test_port_must_be_integer(self, tmp_path):
        bad = tmp_path / "bad.toml"
        bad.write_text('[service]\nport = "80"\ntype = "tcp"\n')
        with pytest.raises(ValueError, match="service.port must be an integer"):
            load_handler(bad)

    def test_no_rules_is_valid(self, tmp_path):
        f = tmp_path / "minimal.toml"
        f.write_text('[service]\nport = 9999\ntype = "tcp"\n')
        config = load_handler(f)
        assert config.port == 9999
        assert config.rules == []

    def test_encoding_defaults_to_utf8(self):
        config = load_handler(HANDLERS_DIR / "ssh_222.toml")
        assert config.encoding == "utf-8"


class TestLoadAllHandlers:
    def test_loads_all_toml_files(self):
        configs = load_all_handlers(HANDLERS_DIR)
        assert len(configs) >= 7
        ports = {c.port for c in configs}
        assert {21, 23, 25, 80, 222, 5900, 6379}.issubset(ports)

    def test_empty_directory_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="No .toml handler files"):
            load_all_handlers(tmp_path)

    def test_nonexistent_directory_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Handler directory not found"):
            load_all_handlers(tmp_path / "nope")
