import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol

from redis.asyncio import Redis, from_url
from redis.exceptions import RedisError

from app.core.config import get_settings

logger = logging.getLogger("app.rate_limit")


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int = 0


class RateLimiter(Protocol):
    async def hit(self, scope: str, identifier: str, limit: int,
                  window_seconds: int = 60) -> RateLimitResult: ...


class RedisRateLimiter:
    """Fixed-window counter in Redis (INCR + EXPIRE).

    Fails OPEN: if Redis is unreachable the request is allowed and a warning is
    logged, so a Redis outage cannot lock every user out. See README limitations.
    """

    def __init__(self, url: str) -> None:
        self._url = url
        self._client: Redis | None = None

    def _redis(self) -> Redis:
        if self._client is None:
            self._client = from_url(self._url)
        return self._client

    async def hit(self, scope: str, identifier: str, limit: int,
                  window_seconds: int = 60) -> RateLimitResult:
        key = f"rl:{scope}:{identifier}"
        try:
            client = self._redis()
            count = await client.incr(key)
            if count == 1:
                await client.expire(key, window_seconds)
            ttl = await client.ttl(key)
            if ttl < 0:  # key without expiry (e.g. a lost EXPIRE): repair it
                await client.expire(key, window_seconds)
                ttl = window_seconds
        except (RedisError, OSError) as exc:
            logger.warning("rate_limit_backend_unavailable error_type=%s", type(exc).__name__)
            return RateLimitResult(allowed=True)
        if count > limit:
            return RateLimitResult(allowed=False, retry_after=max(int(ttl), 1))
        return RateLimitResult(allowed=True)


class InMemoryRateLimiter:
    """Single-process limiter, used in tests (and handy for local experiments)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._windows: dict[str, tuple[float, int]] = {}

    async def hit(self, scope: str, identifier: str, limit: int,
                  window_seconds: int = 60) -> RateLimitResult:
        key = f"{scope}:{identifier}"
        now = self._clock()
        start, count = self._windows.get(key, (now, 0))
        if now - start >= window_seconds:
            start, count = now, 0
        count += 1
        self._windows[key] = (start, count)
        if count > limit:
            return RateLimitResult(allowed=False,
                                   retry_after=max(int(start + window_seconds - now), 1))
        return RateLimitResult(allowed=True)


@lru_cache
def get_rate_limiter() -> RateLimiter:
    return RedisRateLimiter(get_settings().REDIS_URL)
