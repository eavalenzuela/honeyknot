"""Tests for SampleStore: content-addressed dedup of captured payloads."""

import hashlib
import json

from honeyknot.samples import SampleStore


class TestSampleStore:
    def test_first_store_writes_and_flags_new(self, tmp_path):
        store = SampleStore(tmp_path)
        data = b"hello honeyknot"
        digest, is_new, path = store.store(data)
        assert digest == hashlib.sha256(data).hexdigest()
        assert is_new is True
        assert path is not None
        assert path.exists()
        assert path.read_bytes() == data

    def test_repeat_store_dedupes(self, tmp_path):
        store = SampleStore(tmp_path)
        data = b"duplicate payload from many attackers"
        d1, new1, p1 = store.store(data)
        d2, new2, p2 = store.store(data)
        assert d1 == d2
        assert new1 is True
        assert new2 is False
        assert p1 == p2
        # Only one file written
        all_bins = list((tmp_path / "samples").rglob("*.bin"))
        assert len(all_bins) == 1

    def test_sharded_by_first_two_hex_chars(self, tmp_path):
        store = SampleStore(tmp_path)
        digest, _, path = store.store(b"abc")
        assert path.parent.name == digest[:2]
        assert path.parent.parent == tmp_path / "samples"

    def test_min_size_skips_write(self, tmp_path):
        store = SampleStore(tmp_path, min_size=100)
        digest, is_new, path = store.store(b"tiny")
        assert digest  # digest still computed
        assert is_new is False
        assert path is None
        assert not list((tmp_path / "samples").rglob("*.bin"))

    def test_different_contents_different_files(self, tmp_path):
        store = SampleStore(tmp_path)
        store.store(b"one")
        store.store(b"two")
        store.store(b"three")
        all_bins = list((tmp_path / "samples").rglob("*.bin"))
        assert len(all_bins) == 3


class TestSampleMetadata:
    def test_first_hit_creates_sidecar(self, tmp_path):
        store = SampleStore(tmp_path)
        data = b"the payload" * 10
        digest, _, path = store.store(data)
        store.update_meta(digest, size=len(data),
                          peer=("10.0.0.7", 1234),
                          iocs={"urls": ["http://x.test/y"], "ips": [],
                                "downloads": [], "shell": []})
        meta_path = path.with_suffix(".meta.json")
        meta = json.loads(meta_path.read_text())
        assert meta["hit_count"] == 1
        assert meta["size"] == len(data)
        assert meta["peers"] == ["10.0.0.7"]
        assert meta["iocs"]["urls"] == ["http://x.test/y"]
        assert "first_seen" in meta
        assert meta["first_seen"] == meta["last_seen"]

    def test_second_hit_merges(self, tmp_path):
        store = SampleStore(tmp_path)
        data = b"P" * 100
        digest, _, path = store.store(data)
        store.update_meta(digest, size=len(data),
                          peer=("1.1.1.1", 1),
                          iocs={"urls": ["http://a/"], "ips": [],
                                "downloads": [], "shell": []})
        store.update_meta(digest, size=len(data),
                          peer=("2.2.2.2", 1),
                          iocs={"urls": ["http://a/", "http://b/"], "ips": [],
                                "downloads": [], "shell": []})
        meta = json.loads(path.with_suffix(".meta.json").read_text())
        assert meta["hit_count"] == 2
        assert set(meta["peers"]) == {"1.1.1.1", "2.2.2.2"}
        assert set(meta["iocs"]["urls"]) == {"http://a/", "http://b/"}
        assert meta["first_seen"] <= meta["last_seen"]

    def test_peers_capped(self, tmp_path):
        store = SampleStore(tmp_path)
        digest, _, path = store.store(b"X" * 100)
        for i in range(100):
            store.update_meta(digest, size=100, peer=(f"10.0.{i // 256}.{i % 256}", 1))
        meta = json.loads(path.with_suffix(".meta.json").read_text())
        # MAX_PEERS_PER_SAMPLE = 50
        assert len(meta["peers"]) == 50
        assert meta["hit_count"] == 100

    def test_no_digest_noop(self, tmp_path):
        store = SampleStore(tmp_path)
        # Should not raise, should not write anything
        store.update_meta("", size=10, peer=("x", 1))
        assert not list((tmp_path / "samples").rglob("*.meta.json"))
