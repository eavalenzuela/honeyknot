"""End-to-end integration tests against real asyncio listeners.

All handler-level tests use a fake StreamWriter. These exercise
`asyncio.start_server` + `asyncio.open_connection` to catch wire-format
regressions: connection lifecycle, capture writes, event emission,
sample dedup, rate limiting, and the UDP datagram path.

They open ephemeral ports on 127.0.0.1 and clean up.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import socket
import struct

import pytest

from honeyknot.config import ResponseHeaders, Rule, ServiceConfig
from honeyknot.events import EventSink
from honeyknot.ratelimit import RateLimiter
from honeyknot.samples import SampleStore
from honeyknot.server import PortServer, UdpPortServer


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _free_udp() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _read_events(tmp_path) -> list[dict]:
    path = tmp_path / "events.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


async def _quiet_send(port: int, payload: bytes, expect_bytes: bool = False,
                      read_timeout: float = 1.0) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    resp = b""
    try:
        writer.write(payload)
        with contextlib.suppress(Exception):
            await writer.drain()
        if expect_bytes:
            with contextlib.suppress(TimeoutError):
                resp = await asyncio.wait_for(reader.read(4096),
                                              timeout=read_timeout)
    finally:
        writer.close()
        with contextlib.suppress(TimeoutError, Exception):
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
    return resp


class TestTCPServerIntegration:
    def test_regex_connect_data_close_captured(self, tmp_path):
        port = _free_port()
        cfg = ServiceConfig(
            port=port, service_type="http", protocol="regex",
            rules=[Rule(name="root", pattern=re.compile("^GET", re.I),
                        response="root-hit")],
            response_headers=ResponseHeaders(
                status_line="HTTP/1.1 200 OK",
                headers=["Connection: close"],
            ),
            default_response="default",
        )
        events = EventSink(tmp_path)
        samples = SampleStore(tmp_path)
        server = PortServer(cfg, "127.0.0.1", str(tmp_path),
                            events=events, samples=samples)

        async def run():
            await server.start()
            try:
                return await _quiet_send(
                    port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                    expect_bytes=True,
                )
            finally:
                await server.stop()
                events.close()

        resp = asyncio.run(run())
        assert b"root-hit" in resp

        events_list = _read_events(tmp_path)
        kinds = {e["event"] for e in events_list}
        assert "connect" in kinds
        assert "close" in kinds

        raw = list((tmp_path / "raw").glob("*.bin"))
        assert len(raw) == 1
        assert b"GET / HTTP/1.1" in raw[0].read_bytes()

        samples_files = list((tmp_path / "samples").rglob("*.bin"))
        assert len(samples_files) == 1

    def test_rate_limiter_blocks_excess(self, tmp_path):
        port = _free_port()
        cfg = ServiceConfig(port=port, service_type="tcp", protocol="regex",
                            default_response="x")
        events = EventSink(tmp_path)
        limiter = RateLimiter(capacity=2, refill_per_sec=0.0)
        server = PortServer(cfg, "127.0.0.1", str(tmp_path),
                            events=events, samples=SampleStore(tmp_path),
                            rate_limiter=limiter)

        async def run():
            await server.start()
            try:
                for _ in range(5):
                    await _quiet_send(port, b"ping")
            finally:
                await server.stop()
                events.close()

        asyncio.run(run())

        events_list = _read_events(tmp_path)
        rate_limited = [e for e in events_list if e["event"] == "rate_limited"]
        accepted = [e for e in events_list if e["event"] == "connect"]
        assert len(rate_limited) == 3
        assert len(accepted) == 2

    def test_sample_dedup_across_connections(self, tmp_path):
        port = _free_port()
        cfg = ServiceConfig(port=port, service_type="tcp", protocol="regex",
                            default_response="ok")
        events = EventSink(tmp_path)
        samples = SampleStore(tmp_path)
        server = PortServer(cfg, "127.0.0.1", str(tmp_path),
                            events=events, samples=samples)

        async def run():
            await server.start()
            try:
                for _ in range(3):
                    await _quiet_send(port, b"SAMEPAYLOAD")
            finally:
                await server.stop()
                events.close()

        asyncio.run(run())

        samples_files = list((tmp_path / "samples").rglob("*.bin"))
        assert len(samples_files) == 1
        events_list = _read_events(tmp_path)
        new_events = [e for e in events_list if e["event"] == "sample_new"]
        assert len(new_events) == 1


class TestUDPServerIntegration:
    def test_datagram_received_captured_and_answered(self, tmp_path):
        port = _free_udp()
        cfg = ServiceConfig(port=port, service_type="tcp", protocol="dns",
                            transport="udp",
                            protocol_opts={"answer_a": "192.0.2.42"})
        events = EventSink(tmp_path)
        samples = SampleStore(tmp_path)
        server = UdpPortServer(cfg, "127.0.0.1", str(tmp_path),
                               events=events, samples=samples)

        async def run():
            await server.start()
            try:
                qname = b"\x04test\x00"
                header = struct.pack(">HHHHHH", 0xcafe, 0x0100, 1, 0, 0, 0)
                query = header + qname + struct.pack(">HH", 1, 1)

                loop = asyncio.get_running_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.bind(("127.0.0.1", 0))
                sock.sendto(query, ("127.0.0.1", port))
                fut = loop.create_future()

                def _read():
                    try:
                        data, _ = sock.recvfrom(4096)
                        if not fut.done():
                            fut.set_result(data)
                    except BlockingIOError:
                        pass

                loop.add_reader(sock.fileno(), _read)
                try:
                    return await asyncio.wait_for(fut, timeout=1.5)
                finally:
                    loop.remove_reader(sock.fileno())
                    sock.close()
            finally:
                await server.stop()
                events.close()

        reply = asyncio.run(run())
        assert bytes([192, 0, 2, 42]) in reply

        events_list = _read_events(tmp_path)
        assert any(e["event"] == "datagram" for e in events_list)

        raw = list((tmp_path / "raw").glob("*_udp.bin"))
        assert len(raw) == 1

        samples_files = list((tmp_path / "samples").rglob("*.bin"))
        assert len(samples_files) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
