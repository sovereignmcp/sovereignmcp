# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Which JSON-RPC methods may cross the gateway.

Default deny. Every method the gateway does not know about is a path that skips policy:
`resources/read` can read data, `prompts/get` returns server-controlled text, and so on.
Only tools/* is governed by the tool policy; the rest must be opted into with `allowed_methods`
in policy.yaml (exact names or patterns such as "resources/*").
"""
import fnmatch

GOVERNED = frozenset({"tools/call", "tools/list"})
ALWAYS_PASS = frozenset({"initialize", "ping"})


def method_decision(method, allowed_methods=()) -> str:
    """Returns 'govern' (run the tool policy), 'pass' (forward) or 'deny'."""
    if not isinstance(method, str) or not method or len(method) > 128:
        return "deny"
    if method in GOVERNED:
        return "govern"
    if method in ALWAYS_PASS or method.startswith("notifications/"):
        return "pass"
    for pattern in allowed_methods or ():
        if isinstance(pattern, str) and fnmatch.fnmatchcase(method, pattern):
            return "pass"
    return "deny"
