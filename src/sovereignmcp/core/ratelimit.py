# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Failed-authentication limiter: blocks a source after repeated failures, and caps how many failures get logged
(so an attacker can't flood the audit log)."""
import time
from collections import OrderedDict, deque
from threading import Lock


class FailureLimiter:
    def __init__(self, max_failures: int = 10, window_s: float = 60.0, log_cap: int = 20,
                 max_keys: int = 10_000, clock=time.monotonic):
        self.max_failures, self.window, self.log_cap, self.max_keys, self._clock = max_failures, window_s, log_cap, max_keys, clock
        self._fails: OrderedDict = OrderedDict()
        self._lock = Lock()

    def _prune(self, key, now):
        q = self._fails.get(key)
        if q is not None:
            while q and q[0] <= now - self.window:
                q.popleft()
            if not q:
                del self._fails[key]
                return None
        return q

    def record(self, key) -> bool:
        """Records one failure. Returns True if this failure should still be written to the audit log."""
        with self._lock:
            now = self._clock()
            q = self._prune(key, now)
            if q is None:
                q = self._fails[key] = deque()
            q.append(now)
            self._fails.move_to_end(key)
            while len(self._fails) > self.max_keys:
                self._fails.popitem(last=False)
            return len(q) <= self.log_cap

    def blocked(self, key) -> bool:
        with self._lock:
            q = self._prune(key, self._clock())
            return q is not None and len(q) >= self.max_failures

    def retry_after(self, key) -> int:
        with self._lock:
            now = self._clock()
            q = self._prune(key, now)
            return 1 if not q else max(1, int(q[0] + self.window - now) + 1)
