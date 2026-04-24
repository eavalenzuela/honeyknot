"""Tests for SampleStore: content-addressed dedup of captured payloads."""

import hashlib

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
