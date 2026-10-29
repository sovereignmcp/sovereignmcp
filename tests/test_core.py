import os
import sqlite3
import tempfile
import unittest

from sovereignmcp.core.approvals import ApprovalEngine
from sovereignmcp.core.audit import AuditVault
from sovereignmcp.core.identity import AuthError, IdentityEngine

POLICY = os.path.join(os.path.dirname(__file__), "..", "examples", "policy.example.yaml")


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.ids = IdentityEngine(POLICY)

    def h(self, token, agent="alpha_assistant"):
        return {"authorization": f"Bearer {token}", "x-agent-id": agent}

    def test_intersection(self):
        intern = self.ids.authenticate(self.h("demo-intern-token"))
        mgr = self.ids.authenticate(self.h("demo-manager-token"))
        self.assertTrue(self.ids.permits(intern, "read_metrics"))
        self.assertFalse(self.ids.permits(intern, "delete_database"))
        self.assertTrue(self.ids.permits(mgr, "delete_database"))

    def test_manager_routing(self):
        intern = self.ids.authenticate(self.h("demo-intern-token"))
        self.assertEqual(intern["manager_id"], "user_101")

    def test_bad_auth(self):
        with self.assertRaises(AuthError) as c:
            self.ids.authenticate({})
        self.assertEqual(c.exception.status, 401)
        with self.assertRaises(AuthError) as c:
            self.ids.authenticate(self.h("nope"))
        self.assertEqual(c.exception.status, 403)
        with self.assertRaises(AuthError):
            self.ids.authenticate(self.h("demo-intern-token", agent="ghost"))


class AuditTests(unittest.TestCase):
    def test_chain_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            v = AuditVault(os.path.join(d, "a.db"), key="k")
            for i in range(3):
                v.log_event("u", "U", "a", "tools/call", "t", {"i": i, "password": "x"}, "ALLOWED", "ok")
            self.assertTrue(v.verify_chain()["valid"])
            conn = sqlite3.connect(os.path.join(d, "a.db"))
            self.assertIn("REDACTED", conn.execute("SELECT arguments FROM audit_logs WHERE id=1").fetchone()[0])
            conn.execute("UPDATE audit_logs SET decision='BLOCKED' WHERE id=2")
            conn.commit()
            res = v.verify_chain()
            self.assertFalse(res["valid"])
            self.assertEqual(res["corrupted_id"], 2)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.a = ApprovalEngine(os.path.join(self.d.name, "a.db"))
        self.args = ("rohan_id", "Rohan", "mgr", "@mgr", "run_sql", {"query": "DELETE FROM t"}, "r", "b")

    def tearDown(self):
        self.d.cleanup()

    def test_full_flow(self):
        r1 = self.a.request_or_resume(*self.args)
        self.assertEqual(r1["outcome"], "created")
        self.assertEqual(self.a.request_or_resume(*self.args)["outcome"], "pending")
        aid = r1["approval"]["approval_id"]
        self.assertEqual(self.a.decide(aid, "rohan_id", "APPROVED")["code"], 403)   # self-approve
        self.assertEqual(self.a.decide(aid, "other", "APPROVED")["code"], 403)      # wrong manager
        self.assertEqual(self.a.decide(aid, "mgr", "APPROVED")["status"], "APPROVED")
        self.assertEqual(self.a.decide(aid, "mgr", "APPROVED")["code"], 409)        # already decided
        self.assertEqual(self.a.request_or_resume(*self.args)["outcome"], "execute")
        self.assertEqual(self.a.request_or_resume(*self.args)["outcome"], "created")  # single use

    def test_changed_args_need_new_approval(self):
        r1 = self.a.request_or_resume(*self.args)
        self.a.decide(r1["approval"]["approval_id"], "mgr", "APPROVED")
        changed = self.args[:5] + ({"query": "DELETE FROM everything"},) + self.args[6:]
        self.assertEqual(self.a.request_or_resume(*changed)["outcome"], "created")

    def test_expiry(self):
        r = self.a.request_or_resume(*self.args, ttl_minutes=-1)
        self.assertEqual(self.a.decide(r["approval"]["approval_id"], "mgr", "APPROVED")["code"], 410)

    def test_denied(self):
        r = self.a.request_or_resume(*self.args)
        self.a.decide(r["approval"]["approval_id"], "mgr", "DENIED")
        self.assertEqual(self.a.request_or_resume(*self.args)["outcome"], "denied")


if __name__ == "__main__":
    unittest.main()
