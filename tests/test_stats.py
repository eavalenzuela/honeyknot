"""Tests for the offline honeyknot-stats analyzer."""

from __future__ import annotations

import json

from honeyknot import stats


def _write_events(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


SAMPLE_EVENTS = [
    {"event": "connect", "protocol": "ssh", "transport": "tcp", "port": 22,
     "peer": "1.1.1.1:5000"},
    {"event": "connect", "protocol": "ssh", "transport": "tcp", "port": 22,
     "peer": "1.1.1.1:5001"},
    {"event": "connect", "protocol": "http", "transport": "tcp", "port": 80,
     "peer": "2.2.2.2:6000"},
    {"event": "ioc", "protocol": "http", "transport": "tcp", "port": 80,
     "peer": "2.2.2.2:6000", "sha256": "abc123",
     "urls": ["http://evil.test/a", "http://evil.test/a"],
     "ips": ["9.9.9.9"], "onions": ["deadbeefdeadbeef.onion"]},
    {"event": "sample_new", "protocol": "http", "transport": "tcp", "port": 80,
     "peer": "2.2.2.2:6000", "sha256": "abc123", "bytes": 10},
]


class TestBuildReport:
    def test_counts_and_iocs(self, tmp_path):
        path = tmp_path / "events.jsonl"
        _write_events(path, SAMPLE_EVENTS)
        report = stats.build_report(stats.load_events([path]), top=5)
        assert "Total events:    5" in report
        assert "Unique peers:    3" in report
        assert "Unique samples:  1" in report
        assert "connect" in report
        assert "1.1.1.1:5000" in report
        assert "abc123" in report
        # IOC url appears twice within one event → counted twice.
        assert "http://evil.test/a" in report
        assert "deadbeefdeadbeef.onion" in report

    def test_empty_stream(self):
        report = stats.build_report(iter([]))
        assert "Total events:    0" in report


class TestIterEventFiles:
    def test_includes_rotated_backups(self, tmp_path):
        (tmp_path / "events.jsonl").write_text("{}\n")
        (tmp_path / "events.jsonl.1").write_text("{}\n")
        (tmp_path / "events.jsonl.2").write_text("{}\n")
        files = [p.name for p in stats.iter_event_files(tmp_path)]
        assert files[0] == "events.jsonl"
        assert "events.jsonl.1" in files
        assert "events.jsonl.2" in files


class TestMain:
    def test_main_prints_report(self, tmp_path, capsys):
        _write_events(tmp_path / "events.jsonl", SAMPLE_EVENTS)
        rc = stats.main(["-ld", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Total events:" in out
        assert "Events by protocol" in out

    def test_main_missing_log_returns_1(self, tmp_path, capsys):
        rc = stats.main(["-ld", str(tmp_path / "nope")])
        assert rc == 1
        assert "No events found" in capsys.readouterr().err

    def test_main_explicit_events_file(self, tmp_path, capsys):
        f = tmp_path / "custom.jsonl"
        _write_events(f, SAMPLE_EVENTS)
        rc = stats.main(["--events-file", str(f), "-n", "3"])
        assert rc == 0
        assert "Total events:" in capsys.readouterr().out
