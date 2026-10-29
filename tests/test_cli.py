import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import yaml

from sovereignmcp import cli


class CliTests(unittest.TestCase):
    def test_init_writes_policy_with_a_working_random_token(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "policy.yaml")
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cli.main(["init", "--policy", path]), 0)
            token = next(line.strip() for line in out.getvalue().splitlines() if line.startswith("  ") and "export" not in line and line.strip())
            policy = yaml.safe_load(open(path))
            self.assertEqual(policy["users"][0]["token_sha256"], cli.sha256_hex(token))
            self.assertTrue(policy["shadow_mode"])                               # safe default
            self.assertNotIn(policy["users"][0]["token_sha256"], cli.DEMO_HASHES)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["init", "--policy", path]), 1)       # refuses to overwrite
                self.assertEqual(cli.main(["init", "--policy", path, "--force"]), 0)

    def test_hash_token(self):
        out = io.StringIO()
        with redirect_stdout(out):
            cli.main(["hash-token", "demo-intern-token"])
        self.assertEqual(out.getvalue().strip(), cli.sha256_hex("demo-intern-token"))

    def test_demo_tokens_are_refused_unless_demo(self):
        policy = yaml.safe_load(open(os.path.join(os.path.dirname(__file__), "..", "examples", "policy.example.yaml")))
        problems, _ = cli.check_policy_safety(policy, env={"SOVEREIGN_AUDIT_KEY": "x" * 40})
        self.assertTrue(any("DEMO tokens" in p for p in problems))
        problems, _ = cli.check_policy_safety(policy, env={"SOVEREIGN_AUDIT_KEY": "x" * 40}, allow_demo=True)
        self.assertEqual(problems, [])

    def test_missing_audit_key_is_fatal_in_production(self):
        problems, _ = cli.check_policy_safety({"users": []}, env={})
        self.assertTrue(any("SOVEREIGN_AUDIT_KEY" in p for p in problems))
        problems, warnings = cli.check_policy_safety({"users": [], "shadow_mode": True}, env={"SOVEREIGN_AUDIT_KEY": "k" * 40})
        self.assertEqual(problems, [])
        self.assertTrue(any("shadow_mode" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
