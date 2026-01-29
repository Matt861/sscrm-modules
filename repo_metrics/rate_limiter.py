import threading
import time


# ----------------------------
# Simple 1 req/sec rate limiter
# ----------------------------
class RateLimiter:
    def __init__(self, min_interval_seconds: float = 1.05) -> None:
        self.min_interval = float(min_interval_seconds)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.time()
            if now < self._next_allowed:
                time.sleep(self._next_allowed - now)
            self._next_allowed = time.time() + self.min_interval