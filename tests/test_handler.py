"""Tests for honeyknot.handler — request matching and response building."""

import re

from honeyknot.config import ResponseHeaders, Rule, ServiceConfig
from honeyknot.handler import build_response, match_request


def _make_config(rules=None, headers=None, default="", service_type="http"):
    return ServiceConfig(
        port=80,
        service_type=service_type,
        rules=rules or [],
        response_headers=headers,
        default_response=default,
    )


def _make_rule(name, pattern, response):
    return Rule(name=name, pattern=re.compile(pattern, re.IGNORECASE), response=response)


class TestMatchRequest:
    def test_first_matching_rule_wins(self):
        config = _make_config(rules=[
            _make_rule("a", "^GET", "first"),
            _make_rule("b", "^GET /", "second"),
        ])
        result = match_request(config, b"GET / HTTP/1.1\r\n")
        assert b"first" in result

    def test_case_insensitive_match(self):
        config = _make_config(rules=[
            _make_rule("a", "^get", "matched"),
        ])
        result = match_request(config, b"GET / HTTP/1.1\r\n")
        assert b"matched" in result

    def test_default_response_when_no_match(self):
        config = _make_config(rules=[], default="fallback")
        result = match_request(config, b"SOMETHING\r\n")
        assert b"fallback" in result

    def test_empty_when_no_match_and_no_default(self):
        config = _make_config(rules=[], default="")
        result = match_request(config, b"SOMETHING\r\n")
        assert result == b""

    def test_http_headers_prepended(self):
        headers = ResponseHeaders(
            status_line="HTTP/1.1 200 OK",
            headers=["Content-Type: text/html"],
        )
        config = _make_config(
            rules=[_make_rule("a", ".*", "body")],
            headers=headers,
        )
        result = match_request(config, b"GET /\r\n")
        decoded = result.decode()
        assert decoded.startswith("HTTP/1.1 200 OK\r\n")
        assert "Content-Type: text/html\r\n" in decoded
        assert decoded.endswith("body")

    def test_tcp_no_headers(self):
        config = _make_config(
            rules=[_make_rule("a", ".*", "pong")],
            headers=None,
            service_type="tcp",
        )
        result = match_request(config, b"ping")
        assert result == b"pong"

    def test_empty_response_body(self):
        headers = ResponseHeaders(status_line="HTTP/1.1 200 OK", headers=[])
        config = _make_config(
            rules=[_make_rule("head", "^HEAD", "")],
            headers=headers,
        )
        result = match_request(config, b"HEAD / HTTP/1.1\r\n")
        assert b"HTTP/1.1 200 OK" in result

    def test_binary_safe_decoding(self):
        config = _make_config(
            rules=[_make_rule("any", ".*", "got it")],
        )
        # Raw bytes that aren't valid UTF-8
        result = match_request(config, b"\xff\xfe\x00\x01")
        assert b"got it" in result


class TestBuildResponse:
    def test_plain_body_no_headers(self):
        config = _make_config(headers=None, service_type="tcp")
        result = build_response(config, "hello")
        assert result == b"hello"

    def test_headers_and_body(self):
        headers = ResponseHeaders(
            status_line="HTTP/1.1 404 Not Found",
            headers=["Server: test"],
        )
        config = _make_config(headers=headers)
        result = build_response(config, "<h1>nope</h1>")
        parts = result.decode().split("\r\n")
        assert parts[0] == "HTTP/1.1 404 Not Found"
        assert parts[1] == "Server: test"
        assert parts[2] == ""  # blank line separator
        assert parts[3] == "<h1>nope</h1>"
