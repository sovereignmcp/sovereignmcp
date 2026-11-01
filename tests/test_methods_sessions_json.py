import unittest

from sovereignmcp.core.methods import method_decision
from sovereignmcp.core.ratelimit import FailureLimiter
from sovereignmcp.core.safejson import UnsafeJSON, strict_loads
from sovereignmcp.core.sessions import SessionBinder


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class MethodGatingTests(unittest.TestCase):
    def test_tools_are_governed(self):
        self.assertEqual(method_decision("tools/call"), "govern")
        self.assertEqual(method_decision("tools/list"), "govern")

    def test_protocol_basics_pass(self):
        for m in ("initialize", "ping", "notifications/initialized", "notifications/cancelled"):
            self.assertEqual(method_decision(m), "pass", m)

    def test_everything_else_is_denied_by_default(self):
        for m in ("resources/read", "resources/list", "resources/subscribe", "prompts/get", "prompts/list",
                  "completion/complete", "logging/setLevel", "sampling/createMessage", "admin/dropEverything", "Tools/Call"):
            self.assertEqual(method_decision(m), "deny", m)

    def test_malformed_methods_are_denied(self):
        for m in (None, "", 5, ["tools/call"], {"a": 1}, "x" * 500):
            self.assertEqual(method_decision(m), "deny", repr(m)[:30])

    def test_opt_in_via_policy(self):
        self.assertEqual(method_decision("resources/list", ["resources/list"]), "pass")
        self.assertEqual(method_decision("resources/read", ["resources/list"]), "deny")
        self.assertEqual(method_decision("resources/read", ["resources/*"]), "pass")
        self.assertEqual(method_decision("prompts/get", ["resources/*"]), "deny")


class SessionBindingTests(unittest.TestCase):
    def test_only_the_owner_may_use_a_session(self):
        s = SessionBinder()
        s.bind("sess-1", "user_a")
        self.assertTrue(s.check("sess-1", "user_a"))
        self.assertFalse(s.check("sess-1", "user_b"))          # session riding
        self.assertFalse(s.check("never-issued", "user_a"))    # unknown ids are refused, never adopted
        self.assertFalse(s.check("sess-1", ""))

    def test_expiry_and_sliding_window(self):
        clock = Clock()
        s = SessionBinder(ttl_seconds=100, clock=clock)
        s.bind("s", "u")
        clock.t += 60
        self.assertTrue(s.check("s", "u"))                     # refreshes the window
        clock.t += 60
        self.assertTrue(s.check("s", "u"))
        clock.t += 101
        self.assertFalse(s.check("s", "u"))                    # expired

    def test_bounded_memory(self):
        s = SessionBinder(max_sessions=3)
        for i in range(5):
            s.bind(f"s{i}", "u")
        self.assertFalse(s.check("s0", "u"))
        self.assertTrue(s.check("s4", "u"))

    def test_bad_input(self):
        s = SessionBinder()
        for sid in (None, "", "x" * 300, 5):
            self.assertFalse(s.bind(sid, "u"))


class StrictJsonTests(unittest.TestCase):
    def test_normal_json_parses(self):
        self.assertEqual(strict_loads(b'{"a": [1, 2, {"b": null}], "c": "d"}'), {"a": [1, 2, {"b": None}], "c": "d"})

    def test_duplicate_keys_are_refused_at_any_depth(self):
        for raw in (b'{"role":"admin","role":"viewer"}', b'{"role":"viewer","role":"admin"}',
                    b'{"params":{"arguments":{"role":"a","role":"b"}}}', b'[{"x":1,"x":2}]'):
            with self.assertRaises(UnsafeJSON, msg=raw):
                strict_loads(raw)

    def test_nonstandard_constants_and_garbage(self):
        for raw in (b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}'):
            with self.assertRaises(UnsafeJSON):
                strict_loads(raw)
        for raw in (b"", b"{", b"not json", b'{"a":'):
            with self.assertRaises(ValueError):
                strict_loads(raw)

    def test_deep_nesting_is_refused_not_crashed(self):
        with self.assertRaises(UnsafeJSON):
            strict_loads(b"[" * 100000 + b"]" * 100000)


class FailureLimiterTests(unittest.TestCase):
    def test_blocks_after_repeated_failures_then_recovers(self):
        clock = Clock()
        lim = FailureLimiter(max_failures=3, window_s=60, clock=clock)
        for _ in range(2):
            lim.record("1.2.3.4")
        self.assertFalse(lim.blocked("1.2.3.4"))
        lim.record("1.2.3.4")
        self.assertTrue(lim.blocked("1.2.3.4"))
        self.assertFalse(lim.blocked("5.6.7.8"))                # other sources unaffected
        self.assertGreaterEqual(lim.retry_after("1.2.3.4"), 1)
        clock.t += 61
        self.assertFalse(lim.blocked("1.2.3.4"))

    def test_logging_is_capped_so_the_audit_log_cannot_be_flooded(self):
        lim = FailureLimiter(max_failures=1000, log_cap=5, clock=Clock())
        results = [lim.record("x") for _ in range(10)]
        self.assertEqual(results, [True] * 5 + [False] * 5)

    def test_bounded_memory(self):
        lim = FailureLimiter(max_keys=3, clock=Clock())
        for i in range(10):
            lim.record(f"ip{i}")
        self.assertLessEqual(len(lim._fails), 3)


if __name__ == "__main__":
    unittest.main()
