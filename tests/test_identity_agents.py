import hashlib
import os
import tempfile
import unittest

import yaml

from sovereignmcp.core.identity import AuthError, IdentityEngine

H = lambda s: hashlib.sha256(s.encode()).hexdigest()


def engine(extra=None, agents=None):
    policy = {
        "default_agent": "open_agent",
        "agents": agents or {
            "open_agent": {"allowed_tools": ["read_metrics"]},
            "admin_agent": {"allowed_tools": ["*"], "token_sha256": H("agent-secret")},
        },
        "users": [{"id": "u1", "name": "U", "role": "intern", "token_sha256": H("t1"), "allowed_tools": ["*"]}],
    }
    policy.update(extra or {})
    d = tempfile.mkdtemp()
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        yaml.safe_dump(policy, f)
    return IdentityEngine(path)


def headers(agent=None, key=None):
    h = {"authorization": "Bearer t1"}
    if agent:
        h["x-agent-id"] = agent
    if key:
        h["x-agent-key"] = key
    return h


class AgentCredentialTests(unittest.TestCase):
    def test_a_person_cannot_simply_pick_the_powerful_agent(self):
        ids = engine()
        with self.assertRaises(AuthError) as c:
            ids.authenticate(headers("admin_agent"))
        self.assertEqual(c.exception.status, 403)
        with self.assertRaises(AuthError):
            ids.authenticate(headers("admin_agent", "wrong"))

    def test_the_right_credential_works(self):
        ctx = engine().authenticate(headers("admin_agent", "agent-secret"))
        self.assertTrue(engine().permits(ctx, "delete_database"))

    def test_agents_without_a_credential_still_work_by_default(self):
        ctx = engine().authenticate(headers("open_agent"))
        self.assertEqual(ctx["agent_id"], "open_agent")

    def test_require_agent_credentials_makes_them_mandatory(self):
        ids = engine({"require_agent_credentials": True})
        with self.assertRaises(AuthError):
            ids.authenticate(headers("open_agent"))
        ctx = ids.authenticate(headers("admin_agent", "agent-secret"))
        self.assertEqual(ctx["agent_id"], "admin_agent")

    def test_default_agent_credential_is_also_checked(self):
        agents = {"open_agent": {"allowed_tools": ["*"], "token_sha256": H("k")}}
        ids = engine(agents=agents)
        with self.assertRaises(AuthError):
            ids.authenticate(headers())
        self.assertEqual(ids.authenticate(headers(key="k"))["agent_id"], "open_agent")

    def test_allowed_methods_reach_the_context(self):
        self.assertEqual(engine().authenticate(headers("open_agent"))["allowed_methods"], [])
        self.assertEqual(engine({"allowed_methods": ["resources/list"]}).authenticate(headers("open_agent"))["allowed_methods"], ["resources/list"])

    def test_autherror_log_flag(self):
        self.assertTrue(AuthError(403, "x").log)
        self.assertFalse(AuthError(403, "x", log=False).log)


if __name__ == "__main__":
    unittest.main()
