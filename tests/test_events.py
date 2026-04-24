"""Tests for the JSONL EventSink."""

import json

from honeyknot.events import EventSink


class TestEventSink:
    def test_writes_one_json_line_per_event(self, tmp_path):
        sink = EventSink(tmp_path)
        sink.emit("connect", transport="tcp", port=22, protocol="ssh",
                  peer=("10.0.0.1", 54321))
        sink.emit("close", transport="tcp", port=22, protocol="ssh",
                  peer=("10.0.0.1", 54321), bytes_in=128)
        sink.close()

        lines = (tmp_path / "events.jsonl").read_text().splitlines()
        assert len(lines) == 2
        connect = json.loads(lines[0])
        assert connect["event"] == "connect"
        assert connect["peer"] == "10.0.0.1:54321"
        assert connect["transport"] == "tcp"
        assert connect["port"] == 22
        close = json.loads(lines[1])
        assert close["bytes_in"] == 128

    def test_bytes_extras_become_hex(self, tmp_path):
        sink = EventSink(tmp_path)
        sink.emit("protocol", transport="tcp", port=1, protocol="x",
                  peer=("1.2.3.4", 1),
                  sample=b"\xde\xad\xbe\xef")
        sink.close()
        rec = json.loads((tmp_path / "events.jsonl").read_text().strip())
        assert rec["sample"] == "deadbeef"

    def test_no_peer_tolerated(self, tmp_path):
        sink = EventSink(tmp_path)
        sink.emit("protocol", transport="tcp", port=1, protocol="x",
                  name="startup")
        sink.close()
        rec = json.loads((tmp_path / "events.jsonl").read_text().strip())
        assert "peer" not in rec
        assert rec["name"] == "startup"

    def test_rotates_at_max_bytes(self, tmp_path):
        sink = EventSink(tmp_path, max_bytes=200, backup_count=3)
        # Each event line is ~130 bytes; two writes should force rotation.
        for i in range(5):
            sink.emit("connect", transport="tcp", port=1, protocol="x",
                      peer=("1.2.3.4", i + 1))
        sink.close()
        base = tmp_path / "events.jsonl"
        assert base.exists()
        assert (tmp_path / "events.jsonl.1").exists()
        # The oldest rotated backup should be within the backup_count limit
        beyond = tmp_path / "events.jsonl.4"
        assert not beyond.exists()

    def test_backup_count_respected(self, tmp_path):
        sink = EventSink(tmp_path, max_bytes=100, backup_count=2)
        for i in range(10):
            sink.emit("connect", transport="tcp", port=1, protocol="x",
                      peer=("1.2.3.4", i))
        sink.close()
        assert (tmp_path / "events.jsonl").exists()
        assert (tmp_path / "events.jsonl.1").exists()
        assert (tmp_path / "events.jsonl.2").exists()
        assert not (tmp_path / "events.jsonl.3").exists()

    def test_unserializable_dropped_cleanly(self, tmp_path):
        sink = EventSink(tmp_path)

        class Weird:
            def __repr__(self):
                raise RuntimeError("nope")

        sink.emit("protocol", transport="tcp", port=1, protocol="x",
                  peer=("1.1.1.1", 1),
                  weird=Weird())
        # Also emit a normal event after: sink must still work.
        sink.emit("connect", transport="tcp", port=1, protocol="x",
                  peer=("1.1.1.1", 1))
        sink.close()
        lines = (tmp_path / "events.jsonl").read_text().splitlines()
        # Weird event is dropped (default=str raises), normal one stays.
        assert len(lines) == 1
        assert json.loads(lines[0])["event"] == "connect"
