from app.rate_limit import LocalRateLimiter


def test_requests_below_limit_pass():
    limiter = LocalRateLimiter(2)
    assert limiter.check("user|ip", now=0)
    assert limiter.check("user|ip", now=1)


def test_request_over_limit_fails():
    limiter = LocalRateLimiter(1)
    assert limiter.check("user|ip", now=0)
    assert not limiter.check("user|ip", now=1)


def test_window_expiry_allows_request():
    limiter = LocalRateLimiter(1, window_seconds=10)
    assert limiter.check("user|ip", now=0)
    assert limiter.check("user|ip", now=11)


def test_users_have_separate_limits():
    limiter = LocalRateLimiter(1)
    assert limiter.check("a|ip", now=0)
    assert limiter.check("b|ip", now=0)


def test_reset_clears_limits():
    limiter = LocalRateLimiter(1)
    assert limiter.check("user|ip", now=0)
    limiter.reset()
    assert limiter.check("user|ip", now=1)
