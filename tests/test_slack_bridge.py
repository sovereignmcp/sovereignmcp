import hashlib
import os
import tempfile
import unittest

import yaml

from sovereignmcp.core.approvals import ApprovalEngine
from sovereignmcp.core.identity import AuthError, IdentityEngine

H = lambda s: hashlib.sha256(s.encode()).hexdigest()
POLICY = {
    "approval_bridge": {"token_sha256": H("bridge-secret")},
    "agents": {"alpha_assistant": {"allowed_tools": ["*"]}},
    "users": [
        {"id": "user_482", "name": "Rohan", "role": "intern", "manager": "user_101", "slack_user_id": "U_ROHAN", "token_sha256": H("t1"), "allowed_tools": ["*"]},
        {"id": "user_101", "name": "Priya", "role": "manager", "manager": "user_900", "slack_user_id": "U_PRIYA", "token_sha256": H("t2"), "allowed_tools": ["*"]},
        {"id": "user_900", "name": "Sam", "role": "admin", "slack_user_id": "U_SAM", "token_sha256": H("t3"), "allowed_tools": ["*"]},
    ],
}


class SlackBridgeTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        path = os.path.join(self.d.name, "policy.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(POLICY, f)
        self.ids = IdentityEngine(path)
        self.ap = ApprovalEngine(os.path.join(self.d.name, "a.db"))

    def tearDown(self):
        self.d.cleanup()

    def test_bridge_credential(self):
        self.ids.authenticate_bridge({"authorization": "Bearer bridge-secret"})
        for bad in ({}, {"authorization": "Bearer nope"}, {"authorization": "Bearer t2"}):   # a manager token is NOT a bridge token
            with self.assertRaises(AuthError):
                self.ids.authenticate_bridge(bad)

    def test_slack_id_mapping(self):
        self.assertEqual(self.ids.user_by_slack_id("U_PRIYA")["id"], "user_101")
        for bad in ("U_NOBODY", "", None, 5):
            self.assertIsNone(self.ids.user_by_slack_id(bad))

    def test_only_the_routed_manager_can_decide(self):
        r = self.ap.request_or_resume("user_482", "Rohan", "user_101", "@priya", "run_sql", {"query": "DELETE FROM t"}, "r", "b")
        aid = r["approval"]["approval_id"]
        decide = lambda slack_id: self.ap.decide(aid, self.ids.user_by_slack_id(slack_id)["id"], "APPROVED")
        self.assertEqual(decide("U_ROHAN")["code"], 403)   # requester clicking their own approval
        self.assertEqual(decide("U_SAM")["code"], 403)     # another admin, not the routed manager
        self.assertEqual(decide("U_PRIYA")["status"], "APPROVED")


if __name__ == "__main__":
    unittest.main()
