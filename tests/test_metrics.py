"""Tests for MetricsRegistry + serve_metrics."""

import asyncio
import socket

import pytest

from honeyknot.events import EventSink
from honeyknot.metrics import MetricsRegistry, _esc, serve_metrics


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestRegistry:
    def test_counts_by_kind_port_proto_transport(self):
        r = MetricsRegistry()
        r.record_event("connect", port=22, protocol="ssh", transport="tcp")
        r.record_event("connect", port=22, protocol="ssh", transport="tcp")
        r.record_event("close", port=22, protocol="ssh", transport="tcp")
        out = r.render().decode()
        assert 'honeyknot_events_total{event="connect",' in out
        assert 'port="22"} 2' in out
        assert 'event="close"' in out

    def test_escapes_special_chars_in_labels(self):
        r = MetricsRegistry()
        r.record_event('odd"name', port=1, protocol="p", transport="tcp")
        out = r.render().decode()
        assert 'event="odd\\"name"' in out

    def test_event_sink_bumps_registry(self, tmp_path):
        r = MetricsRegistry()
        sink = EventSink(tmp_path, metrics=r)
        sink.emit("connect", transport="tcp", port=22, protocol="ssh",
                  peer=("1.1.1.1", 1))
        sink.emit("close", transport="tcp", port=22, protocol="ssh",
                  peer=("1.1.1.1", 1), bytes_in=0)
        sink.close()
        out = r.render().decode()
        assert 'event="connect",protocol="ssh"' in out
        assert 'event="close"' in out

    def test_samples_gauge_counts_files(self, tmp_path):
        r = MetricsRegistry()
        samples_dir = tmp_path / "samples"
        (samples_dir / "ab").mkdir(parents=True)
        (samples_dir / "ab" / "x.bin").write_bytes(b"x")
        (samples_dir / "ab" / "y.bin").write_bytes(b"y")
        r.samples_path = samples_dir
        out = r.render().decode()
        assert "honeyknot_unique_samples 2" in out

    def test_esc_helper(self):
        assert _esc('a"b\\c\nd') == 'a\\"b\\\\c\\nd'

    def test_build_info_and_uptime_present(self):
        from honeyknot import __version__
        r = MetricsRegistry()
        out = r.render().decode()
        assert f'honeyknot_build_info{{version="{__version__}"}} 1' in out
        assert "honeyknot_uptime_seconds " in out

    def test_bytes_captured_counter(self):
        r = MetricsRegistry()
        r.record_bytes(100, port=80, protocol="http", transport="tcp")
        r.record_bytes(50, port=80, protocol="http", transport="tcp")
        r.record_bytes(0, port=80, protocol="http", transport="tcp")  # ignored
        out = r.render().decode()
        assert 'honeyknot_bytes_captured_total{protocol="http",' in out
        assert 'transport="tcp",port="80"} 150' in out

    def test_bytes_captured_absent_when_zero(self):
        r = MetricsRegistry()
        out = r.render().decode()
        assert "honeyknot_bytes_captured_total" not in out


class TestServeMetrics:
    def test_serve_and_scrape(self):
        r = MetricsRegistry()
        r.record_event("connect", port=80, protocol="http", transport="tcp")
        port = _free_port()

        async def run():
            server = await serve_metrics(r, f"127.0.0.1:{port}")
            assert server is not None
            try:
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port,
                )
                writer.write(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(8192), timeout=2.0)
                writer.close()
                await writer.wait_closed()
                assert b"HTTP/1.1 200 OK" in data
                assert b"honeyknot_events_total" in data
                assert b'event="connect"' in data
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run())

    def test_non_metrics_path_404(self):
        r = MetricsRegistry()
        port = _free_port()

        async def run():
            server = await serve_metrics(r, f"127.0.0.1:{port}")
            try:
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port,
                )
                writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                writer.close()
                await writer.wait_closed()
                assert b"404 Not Found" in data
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run())

    def test_empty_bind_disables(self):
        async def run():
            assert await serve_metrics(MetricsRegistry(), "") is None
        asyncio.run(run())

    def test_invalid_bind_returns_none(self):
        async def run():
            assert await serve_metrics(MetricsRegistry(), "bogus") is None
            assert await serve_metrics(
                MetricsRegistry(), "127.0.0.1:notaport",
            ) is None
        asyncio.run(run())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
