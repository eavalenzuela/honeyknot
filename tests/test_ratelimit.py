"""Tests for the per-source RateLimiter."""

import time

from honeyknot.ratelimit import RateLimiter


class TestRateLimiter:
    def test_initial_burst_allowed_up_to_capacity(self):
        rl = RateLimiter(capacity=3, refill_per_sec=0.0)
        assert rl.check("1.2.3.4") is True
        assert rl.check("1.2.3.4") is True
        assert rl.check("1.2.3.4") is True
        assert rl.check("1.2.3.4") is False

    def test_separate_ips_independent(self):
        rl = RateLimiter(capacity=1, refill_per_sec=0.0)
        assert rl.check("1.1.1.1") is True
        assert rl.check("1.1.1.1") is False
        # second IP still has its full bucket
        assert rl.check("2.2.2.2") is True

    def test_refill_restores_tokens(self, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr(time, "monotonic", lambda: clock[0])
        rl = RateLimiter(capacity=1, refill_per_sec=2.0)
        assert rl.check("x") is True
        assert rl.check("x") is False
        clock[0] += 0.6  # 1.2 tokens accumulated → caps at capacity=1
        assert rl.check("x") is True
        assert rl.check("x") is False

    def test_capacity_zero_disables(self):
        rl = RateLimiter(capacity=0, refill_per_sec=0.0)
        assert rl.disabled is True
        for _ in range(1000):
            assert rl.check("10.0.0.1") is True

    def test_idle_buckets_evicted(self, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr(time, "monotonic", lambda: clock[0])
        rl = RateLimiter(capacity=5, refill_per_sec=0.0, idle_evict_after=10)
        rl.check("old.ip")
        assert "old.ip" in rl._buckets
        clock[0] += 100.0
        # Any check > 30s after last sweep triggers the sweep
        rl.check("fresh.ip")
        assert "old.ip" not in rl._buckets
