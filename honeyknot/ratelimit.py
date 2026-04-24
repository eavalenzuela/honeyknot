"""Per-source rate limiter: token bucket keyed by peer IP.

A single aggressive scanner can open thousands of connections per second
against a honeypot, each producing a raw capture file and JSONL events.
Without a limiter, that fills the disk in minutes. This keeps a small
token bucket per source IP; when the bucket is empty, new
connections/datagrams from that IP are dropped (after being counted and
logged).

Not a defense against a real DDoS — if the attacker's goal is denial, no
user-space limiter helps. This is about bounding *cost per attacker* so a
single noisy probe doesn't starve signal from everyone else.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class RateLimiter:
    """Per-IP token bucket.

    Each IP gets `capacity` tokens and refills at `refill_per_sec` tokens
    per second. `check(ip)` consumes one token; returns True if allowed,
    False if the bucket is empty. `disabled` bypasses the limiter entirely
    so tests and trusted operators don't pay for the lookup.

    Old buckets are pruned on `check` when we happen to see them expired,
    to keep memory bounded under a slow trickle of unique IPs.
    """

    def __init__(self, capacity: float = 20.0, refill_per_sec: float = 5.0,
                 idle_evict_after: float = 300.0):
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self.idle_evict_after = float(idle_evict_after)
        self.disabled = capacity <= 0
        self._buckets: dict[str, _Bucket] = {}
        self._last_sweep = time.monotonic()

    def check(self, ip: str) -> bool:
        if self.disabled:
            return True
        now = time.monotonic()
        bucket = self._buckets.get(ip)
        if bucket is None:
            bucket = _Bucket(tokens=self.capacity, last_refill=now)
            self._buckets[ip] = bucket
        else:
            elapsed = now - bucket.last_refill
            if elapsed > 0:
                bucket.tokens = min(
                    self.capacity,
                    bucket.tokens + elapsed * self.refill_per_sec,
                )
                bucket.last_refill = now

        # Opportunistic sweep: every ~30s check for idle buckets.
        if now - self._last_sweep > 30.0:
            self._sweep(now)
            self._last_sweep = now

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True
        return False

    def _sweep(self, now: float) -> None:
        cutoff = now - self.idle_evict_after
        dead = [ip for ip, b in self._buckets.items() if b.last_refill < cutoff]
        for ip in dead:
            del self._buckets[ip]
