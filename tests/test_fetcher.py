"""Tests for the opt-in payload fetcher.

The safety properties matter more than the happy path here: the fetcher is
the only component that makes an outbound connection, driven by an
attacker-controlled URL. The SSRF guard, the byte ceiling, and the
off-by-default behavior each get direct coverage.
"""

from __future__ import annotations

import asyncio
import http.server
import threading
from unittest.mock import patch

import pytest

from honeyknot.fetcher import PayloadFetcher, _reject_address


class _Sink:
    def __init__(self):
        self.records: list[tuple[str, dict]] = []

    def emit(self, event, **fields):
        self.records.append((event, fields))

    def of(self, event):
        return [f for n, f in self.records if n == event]


@pytest.fixture
def sink():
    return _Sink()


class TestAddressVetting:
    @pytest.mark.parametrize("addr", [
        "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254",
        "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1",
    ])
    def test_non_public_addresses_are_rejected(self, addr):
        assert _reject_address(addr) is not None

    @pytest.mark.parametrize("addr", ["8.8.8.8", "185.199.108.153", "2606:4700::1"])
    def test_public_addresses_are_allowed(self, addr):
        assert _reject_address(addr) is None

    def test_unparseable_address_is_rejected(self):
        assert _reject_address("not-an-ip") is not None

    def test_vet_host_rejects_a_private_resolution(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink)
        with patch("socket.getaddrinfo",
                   return_value=[(2, 1, 6, "", ("127.0.0.1", 80))]):
            assert fetcher._vet_host("evil.example") is not None

    def test_vet_host_rejects_a_split_resolution(self, sink):
        # One public and one private address is a rebinding setup; refuse.
        fetcher = PayloadFetcher(enabled=True, events=sink)
        with patch("socket.getaddrinfo", return_value=[
                (2, 1, 6, "", ("8.8.8.8", 80)),
                (2, 1, 6, "", ("10.0.0.1", 80))]):
            assert fetcher._vet_host("evil.example") is not None

    def test_vet_host_allows_a_public_resolution(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink)
        with patch("socket.getaddrinfo",
                   return_value=[(2, 1, 6, "", ("8.8.8.8", 80))]):
            assert fetcher._vet_host("example.com") is None

    def test_dns_failure_is_reported_not_raised(self, sink):
        import socket
        fetcher = PayloadFetcher(enabled=True, events=sink)
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            assert "dns failure" in fetcher._vet_host("nx.example")

    def test_allow_private_disables_the_guard(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink, allow_private=True)
        assert fetcher._vet_host("127.0.0.1") is None


class TestScheduling:
    def test_disabled_by_default(self, sink):
        assert PayloadFetcher(events=sink).enabled is False

    def test_disabled_fetcher_queues_nothing(self, sink):
        fetcher = PayloadFetcher(events=sink, on_payload=lambda **kw: None)
        assert fetcher.schedule(["http://x/y"], peer=("1.2.3.4", 1),
                                port=23, protocol="telnet") == 0

    def test_no_callback_queues_nothing(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink)
        assert fetcher.schedule(["http://x/y"], peer=("1.2.3.4", 1),
                                port=23, protocol="telnet") == 0

    @pytest.mark.parametrize("url", [
        "ftp://x/y", "tftp://x/y", "file:///etc/passwd", "gopher://x",
        "not-a-url", "",
    ])
    def test_unsupported_schemes_are_skipped(self, sink, url):
        fetcher = PayloadFetcher(enabled=True, events=sink,
                                 on_payload=lambda **kw: None)
        assert fetcher._should_fetch(url) is False

    def test_duplicate_urls_are_fetched_once(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink,
                                 on_payload=lambda **kw: None)
        assert fetcher._should_fetch("http://x/y") is True
        fetcher._seen.add("http://x/y")
        assert fetcher._should_fetch("http://x/y") is False

    def test_total_budget_is_enforced(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink, max_total=2,
                                 on_payload=lambda **kw: None)
        fetcher._fetched = 2
        assert fetcher._should_fetch("http://x/new") is False


class TestBlockingFetch:
    def test_rejects_private_destination_before_connecting(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink)
        status, body, ctype, error = fetcher._blocking_fetch(
            "http://127.0.0.1:1/x")
        assert status is None and body == b""
        assert "non-public" in error

    def test_rejects_unsupported_scheme(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink)
        _, _, _, error = fetcher._blocking_fetch("ftp://1.2.3.4/x")
        assert "unsupported url" in error

    def test_missing_host_is_handled(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink)
        _, _, _, error = fetcher._blocking_fetch("http:///x")
        assert error is not None


class _Handler(http.server.BaseHTTPRequestHandler):
    payload = b"\x7fELF" + b"A" * 2048

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/payload")
            self.end_headers()
            return
        body = b"B" * 100_000 if self.path == "/big" else self.payload
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def http_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


class TestEndToEnd:
    """Real sockets, against a local server, with the guard opted out."""

    def _run(self, fetcher, url):
        stored: list[bytes] = []

        def on_payload(*, data, url, peer, port, protocol):
            stored.append(data)
            return "deadbeef"

        fetcher.on_payload = on_payload

        async def go():
            fetcher.schedule([url], peer=("9.9.9.9", 4444), port=23,
                             protocol="telnet")
            await asyncio.gather(*list(fetcher._tasks))

        asyncio.run(go())
        return stored

    def test_fetches_and_stores(self, sink, http_server):
        fetcher = PayloadFetcher(enabled=True, events=sink, allow_private=True)
        stored = self._run(fetcher, f"{http_server}/payload")
        assert stored and stored[0][:4] == b"\x7fELF"
        event = sink.of("payload_fetch")[0]
        assert event["status"] == 200
        assert event["sha256"] == "deadbeef"
        assert event["bytes"] == len(_Handler.payload)
        assert event["error"] is None

    def test_follows_a_redirect(self, sink, http_server):
        fetcher = PayloadFetcher(enabled=True, events=sink, allow_private=True)
        stored = self._run(fetcher, f"{http_server}/redirect")
        assert stored and stored[0][:4] == b"\x7fELF"

    def test_byte_ceiling_truncates(self, sink, http_server):
        fetcher = PayloadFetcher(enabled=True, events=sink, allow_private=True,
                                 max_bytes=1024)
        stored = self._run(fetcher, f"{http_server}/big")
        assert len(stored[0]) == 1024
        assert sink.of("payload_fetch")[0]["error"] == "truncated at max_bytes"

    def test_connection_failure_is_reported_not_raised(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink, allow_private=True,
                                 timeout=0.5)
        stored = self._run(fetcher, "http://127.0.0.1:1/nothing")
        assert stored == []
        assert sink.of("payload_fetch")[0]["error"] is not None

    def test_guard_still_blocks_localhost_when_not_opted_out(self, sink,
                                                             http_server):
        fetcher = PayloadFetcher(enabled=True, events=sink)
        stored = self._run(fetcher, f"{http_server}/payload")
        assert stored == []
        assert "non-public" in sink.of("payload_fetch")[0]["error"]


class TestShutdown:
    def test_close_cancels_in_flight_tasks(self, sink):
        fetcher = PayloadFetcher(enabled=True, events=sink, allow_private=True,
                                 on_payload=lambda **kw: None, timeout=30)

        async def go():
            fetcher.schedule(["http://127.0.0.1:1/x"], peer=("1.1.1.1", 1),
                             port=80, protocol="http")
            assert fetcher._tasks
            await fetcher.close()
            assert all(t.done() for t in list(fetcher._tasks) or [])

        asyncio.run(go())
