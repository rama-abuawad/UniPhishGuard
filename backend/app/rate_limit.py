from __future__ import annotations

import time
from collections import OrderedDict
from threading import Lock


class LocalRateLimiter:
    """Bounded single-process limiter; replaceable by a distributed adapter later."""

    def __init__(self, maximum: int, window_seconds: int = 60, max_keys: int = 10_000):
        self.maximum = maximum
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._requests: OrderedDict[str, list[float]] = OrderedDict()
        self._lock = Lock()

    def check(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            recent = [stamp for stamp in self._requests.pop(key, []) if now - stamp < self.window_seconds]
            if len(recent) >= self.maximum:
                self._requests[key] = recent
                return False
            recent.append(now)
            self._requests[key] = recent
            self._cleanup(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._requests.clear()

    def _cleanup(self, now: float) -> None:
        expired = [key for key, stamps in self._requests.items() if not stamps or now - stamps[-1] >= self.window_seconds]
        for key in expired:
            self._requests.pop(key, None)
        while len(self._requests) > self.max_keys:
            self._requests.popitem(last=False)
