# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Binds MCP session ids to the person who initialized them.

Without this, anyone with a valid token who learns another person's `mcp-session-id` could send it
through the gateway and ride that person's upstream session. In memory only: after a gateway restart
clients get 404 and re-initialize, which is what the MCP spec expects.
"""
import hmac
import time
from collections import OrderedDict
from threading import Lock


class SessionBinder:
    def __init__(self, ttl_seconds: float = 8 * 3600, max_sessions: int = 10_000, clock=time.monotonic):
        self._ttl, self._max, self._clock = ttl_seconds, max_sessions, clock
        self._sessions: OrderedDict = OrderedDict()
        self._lock = Lock()

    def bind(self, session_id, user_id) -> bool:
        if not isinstance(session_id, str) or not session_id or len(session_id) > 256 or not user_id:
            return False
        with self._lock:
            self._sessions[session_id] = (user_id, self._clock() + self._ttl)
            self._sessions.move_to_end(session_id)
            while len(self._sessions) > self._max:
                self._sessions.popitem(last=False)
        return True

    def check(self, session_id, user_id) -> bool:
        """True only if this session was bound to THIS user and has not expired. Unknown ids are refused."""
        if not isinstance(session_id, str) or not user_id:
            return False
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is None:
                return False
            owner, expires = entry
            now = self._clock()
            if expires <= now:
                del self._sessions[session_id]
                return False
            if not hmac.compare_digest(owner.encode(), str(user_id).encode()):
                return False
            self._sessions[session_id] = (owner, now + self._ttl)      # sliding expiry
            return True
