from app.services.rate_limit import InMemoryRateLimiter, RedisRateLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


async def test_allows_up_to_limit_then_blocks():
    limiter = InMemoryRateLimiter()
    for _ in range(3):
        assert (await limiter.hit("login", "1.1.1.1", limit=3)).allowed
    blocked = await limiter.hit("login", "1.1.1.1", limit=3)
    assert blocked.allowed is False
    assert blocked.retry_after >= 1


async def test_window_resets_after_expiry():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(clock=clock)
    for _ in range(3):
        await limiter.hit("login", "1.1.1.1", limit=2)
    assert (await limiter.hit("login", "1.1.1.1", limit=2)).allowed is False
    clock.now += 61
    assert (await limiter.hit("login", "1.1.1.1", limit=2)).allowed is True


async def test_identifiers_are_independent():
    limiter = InMemoryRateLimiter()
    for _ in range(2):
        await limiter.hit("login", "1.1.1.1", limit=2)
    assert (await limiter.hit("login", "1.1.1.1", limit=2)).allowed is False
    assert (await limiter.hit("login", "2.2.2.2", limit=2)).allowed is True


async def test_scopes_are_independent():
    limiter = InMemoryRateLimiter()
    for _ in range(2):
        await limiter.hit("login", "1.1.1.1", limit=2)
    assert (await limiter.hit("login", "1.1.1.1", limit=2)).allowed is False
    assert (await limiter.hit("upload", "1.1.1.1", limit=2)).allowed is True


async def test_redis_limiter_fails_open_when_redis_unreachable():
    limiter = RedisRateLimiter("redis://localhost:6399/0")  # nothing listens here
    result = await limiter.hit("login", "1.1.1.1", limit=1)
    assert result.allowed is True
