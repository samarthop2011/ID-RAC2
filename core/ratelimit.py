"""AIMD limiter: back off hard on 429/503, recover slowly on success."""
from __future__ import annotations

import asyncio
import time


class AdaptiveLimiter:
    def __init__(self, rps: float, floor: float = 5.0, ceiling: float = 4000.0):
        self.rps = rps
        self.floor, self.ceiling = floor, ceiling
        self.tokens = 1.0
        self.stamp = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self.lock:
                now = time.monotonic()
                self.tokens = min(1.0, self.tokens + (now - self.stamp) * self.rps)
                self.stamp = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rps
            await asyncio.sleep(wait)

    def on_throttle(self) -> None:
        self.rps = max(self.floor, self.rps * 0.6)

    def on_success(self) -> None:
        self.rps = min(self.ceiling, self.rps * 1.02)
