import json
import unittest

from sovereignmcp.core.audit import luhn_ok, redact, scrub

# Sample secrets are assembled at runtime so this file never contains a real-looking literal
# (secret scanners, including ours, would flag it).
SLACK = "xo" + "xb-" + "1234567890-abcdefghijkl"
SLACK_APP = "xa" + "pp-1-" + "A0123456789-0123456789abcdef"
AWS = "AK" + "IA" + "IOSFODNN7EXAMPLE"
GITHUB = "gh" + "p_" + "A" * 36
JWT = ".".join(["ey" + "JhbGciOiJIUzI1NiJ9", "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0", "abcdefghijk12345"])
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END " + "RSA PRIVATE KEY-----"


class RedactionTests(unittest.TestCase):
    def assertScrubbed(self, text, secret):
        out = scrub(text)
        self.assertNotIn(secret, out, f"{secret[:6]}... survived in: {out}")

    def test_secrets_inside_values_are_removed(self):
        cases = [
            ("curl -H 'Authorization: Bearer " + "abc123def456ghi789jkl'", "abc123def456ghi789jkl"),
            ("token is " + SLACK, SLACK), ("app " + SLACK_APP, SLACK_APP), ("key=" + AWS + " region", AWS),
            ("push with " + GITHUB, GITHUB), ("jwt " + JWT, JWT), (PEM, "MIIBOgIBAAJBAKj34"),
            ("sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0", "A1b2C3d4E5f6G7h8I9j0"),
            ("sk-" + "proj-abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx"),
            ("UPDATE users SET password='hunter2secret' WHERE id=1", "hunter2secret"),
            ("postgres://admin:s3cretpass@db.internal/app", "s3cretpass"),
            ('{"note": "api_key: zzzTOPSECRETzzz"}', "zzzTOPSECRETzzz"),
        ]
        for text, secret in cases:
            self.assertScrubbed(text, secret)

    def test_structure_survives(self):
        out = scrub("UPDATE users SET password='hunter2secret' WHERE id=1")
        self.assertIn("UPDATE users SET password", out)
        self.assertIn("WHERE id=1", out)
        self.assertIn("postgres://admin:", scrub("postgres://admin:s3cretpass@db.internal/app"))
        self.assertIn("@db.internal/app", scrub("postgres://admin:s3cretpass@db.internal/app"))

    def test_card_numbers_only_when_luhn_valid(self):
        self.assertNotIn("4111", scrub("card 4111 1111 1111 1111 expires"))
        self.assertNotIn("4111", scrub("card 4111-1111-1111-1111"))
        order_id = "1234567890123"
        self.assertFalse(luhn_ok(order_id))
        self.assertIn(order_id, scrub(f"order {order_id} shipped"))      # not a card: left alone

    def test_ordinary_text_is_untouched(self):
        for text in ("SELECT * FROM orders WHERE id = 5", "ls -la /var/log", "https://example.com/page?q=1",
                     "Q3 revenue was 4.8M across 310 orgs", "git log --oneline"):
            self.assertEqual(scrub(text), text)

    def test_redact_walks_structures_and_keeps_key_based_rules(self):
        data = {"query": "select 1", "api_key": "plainvalue", "nested": [{"cmd": "echo Bearer " + "abc123def456ghi789jkl"}],
                "n": 5, "ok": True, "none": None}
        out = redact(data)
        self.assertEqual(out["api_key"], "***REDACTED***")
        self.assertNotIn("abc123def456ghi789jkl", json.dumps(out))
        self.assertEqual((out["query"], out["n"], out["ok"], out["none"]), ("select 1", 5, True, None))

    def test_no_catastrophic_backtracking(self):
        import time
        nasty = ("a" * 50000) + " " + ("1 " * 20000) + ("-" * 30000)
        t = time.time()
        scrub(nasty)
        self.assertLess(time.time() - t, 3.0)


if __name__ == "__main__":
    unittest.main()
