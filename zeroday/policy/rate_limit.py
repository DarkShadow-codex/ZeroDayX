"""Rate Limiting Engine for ZeroDay v2.0.

Provides sliding window token-bucket rate limiting per target and scan.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    requests_per_second: float = 10.0
    burst_capacity: int = 20


class TokenBucket:
    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = rate  # tokens added per second
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(float(self.capacity), self.tokens + elapsed * self.rate)

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def wait_and_acquire(self, tokens: float = 1.0, timeout: float = 10.0) -> bool:
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if await self.acquire(tokens):
                return True
            await asyncio.sleep(0.05)
        return False


class RateLimiter:
    """Manages rate limits across targets, domains, and global scan operations."""

    def __init__(self, default_config: RateLimitConfig | None = None) -> None:
        self.default_config = default_config or RateLimitConfig()
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def get_bucket(self, target_key: str) -> TokenBucket:
        async with self._lock:
            if target_key not in self._buckets:
                self._buckets[target_key] = TokenBucket(
                    rate=self.default_config.requests_per_second,
                    capacity=self.default_config.burst_capacity,
                )
            return self._buckets[target_key]

    async def acquire(self, target_key: str, tokens: float = 1.0) -> bool:
        bucket = await self.get_bucket(target_key)
        return await bucket.acquire(tokens)

    async def wait_and_acquire(
        self, target_key: str, tokens: float = 1.0, timeout: float = 10.0
    ) -> bool:
        bucket = await self.get_bucket(target_key)
        return await bucket.wait_and_acquire(tokens, timeout=timeout)
