"""In-process token-bucket rate limiter.

Each key (a user id, or ``login:<client-ip>``) gets a bucket that refills at
``rate_per_minute`` and holds at most that many tokens (allowing a short burst).

Limitation: state is per process. With several worker processes each enforces
its own budget; a shared store (e.g. Redis) would be needed for a global limit.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass

MAX_KEYS = 50_000


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(
        self, rate_per_minute: int, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.capacity = float(rate_per_minute)
        self.rate = rate_per_minute / 60.0
        self._buckets: dict[str, _Bucket] = {}
        self._now = clock

    def hit(self, key: str, cost: float = 1.0) -> float:
        """Consume ``cost`` tokens. Returns 0 if allowed, else seconds to wait."""
        now = self._now()
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= MAX_KEYS:
                self._prune(now)
            if len(self._buckets) >= MAX_KEYS:
                # Table full of live buckets: refuse new keys rather than evicting
                # exhausted ones (eviction would let an attacker reset lockouts).
                return 1.0 / self.rate
            bucket = self._buckets[key] = _Bucket(self.capacity, now)
        bucket.tokens = min(self.capacity, bucket.tokens + (now - bucket.updated) * self.rate)
        bucket.updated = now
        if bucket.tokens >= cost:
            bucket.tokens -= cost
            return 0.0
        return (cost - bucket.tokens) / self.rate

    def _prune(self, now: float) -> None:
        """Drop buckets that have fully refilled (they carry no state)."""
        full_after = self.capacity / self.rate
        stale = [k for k, b in self._buckets.items() if now - b.updated >= full_after]
        for k in stale:
            del self._buckets[k]


def retry_after_header(wait: float) -> str:
    return str(max(1, math.ceil(wait)))
