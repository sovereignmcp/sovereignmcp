import asyncio
import copy
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from sovereignmcp.cloud import egress
from sovereignmcp.cloud.agent import CloudAgent
from tests.helpers_signing import generate, sign_message
from sovereignmcp.cloud.verify import load_pinned_keys, process_decision
from sovereignmcp.core.approvals import ApprovalEngine

SECRET = bytes.fromhex("11" * 32)
GW = "gw_8f3k2"
USERS = ["user_482", "user_101", "user_900"]        # intern, his manager, cto
ARGS = {"query": "DELETE FROM test_data WHERE quarter='Q2'"}
VERDICT = {"reason": "Non-read SQL needs approval (DELETE on ['test_data'], WHERE clause: yes)",
           "blast_radius": "DELETE on ['test_data'], WHERE clause: yes"}
FMT = "%Y-%m-%dT%H:%M:%SZ"


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = ApprovalEngine(os.path.join(self.tmp.name, "a.db"))
        self.priv, self.pub = generate()
        self.keys = load_pinned_keys(f"k1:{self.pub}")
        r = self.engine.request_or_resume("user_482", "Rohan", "user_101", "@priya", "run_sql", ARGS, "r", "b")
        self.appr = r["approval"]
        self.now = datetime.now(timezone.utc)

    def tearDown(self):
        self.tmp.cleanup()

    def decision(self, **override):
        msg = {
            "schema": "sovereign.approval_decision.v1", "gateway_id": GW, "approval_id": self.appr["approval_id"],
            "decision": "APPROVED", "approver_ref": egress.opaque_ref(SECRET, "user", "user_101"),
            "args_fingerprint": egress.args_fingerprint(SECRET, "run_sql", ARGS),
            "decided_at": self.now.strftime(FMT), "valid_until": (self.now + timedelta(minutes=15)).strftime(FMT),
            "nonce": egress.nonce_for(SECRET, self.appr["approval_id"]),
        }
        msg.update(override)
        return msg

    def signed(self, **override):
        return sign_message(self.decision(**override), self.priv, "k1")

    def process(self, msg):
        return process_decision(
            msg, secret=SECRET, keys=self.keys, gateway_id=GW, get_approval=self.engine.get,
            user_ids=lambda: USERS, decide=lambda aid, uid, d: self.engine.decide(aid, uid, d), now=self.now)

    def assertRejected(self, msg, code):
        res = self.process(msg)
        self.assertEqual((res["outcome"], res["code"]), ("rejected", code), res)
        self.assertEqual(self.engine.get(self.appr["approval_id"])["status"], "PENDING")   # nothing changed

    # ---- the happy path, end to end through the real approval engine ----
    def test_valid_decision_is_applied_and_unlocks_exactly_one_execution(self):
        res = self.process(self.signed())
        self.assertEqual((res["outcome"], res["code"], res["approver_user_id"]), ("applied", "ok", "user_101"))
        again = self.engine.request_or_resume("user_482", "Rohan", "user_101", "@priya", "run_sql", ARGS, "r", "b")
        self.assertEqual(again["outcome"], "execute")
        self.assertEqual(self.engine.request_or_resume("user_482", "Rohan", "user_101", "@priya", "run_sql", ARGS, "r", "b")["outcome"], "created")

    def test_denied_decision_blocks(self):
        self.assertEqual(self.process(self.signed(decision="DENIED"))["outcome"], "applied")
        self.assertEqual(self.engine.request_or_resume("user_482", "Rohan", "user_101", "@priya", "run_sql", ARGS, "r", "b")["outcome"], "denied")

    # ---- signature ----
    def test_tampered_after_signing(self):
        msg = self.signed(decision="DENIED")
        msg["decision"] = "APPROVED"
        self.assertRejected(msg, "bad_signature")

    def test_wrong_signing_key(self):
        other_priv, _ = generate()
        self.assertRejected(sign_message(self.decision(), other_priv, "k1"), "bad_signature")

    def test_unknown_kid(self):
        self.assertRejected(sign_message(self.decision(), self.priv, "k9"), "unknown_kid")

    def test_unsigned_or_malformed_signature(self):
        msg = self.decision(kid="k1")
        self.assertRejected(msg, "schema")
        self.assertRejected({**msg, "sig": "ed25519:" + "A" * 86 + "=="}, "bad_signature")
        self.assertRejected({**self.signed(), "sig": "nonsense"}, "schema")

    def test_kid_is_covered_by_the_signature(self):
        self.keys["k2"] = self.keys["k1"]
        msg = self.signed()
        msg["kid"] = "k2"
        self.assertRejected(msg, "bad_signature")

    # ---- binding to OUR record ----
    def test_wrong_gateway(self):
        self.assertRejected(self.signed(gateway_id="gw_other99"), "wrong_gateway")

    def test_unknown_approval_id(self):
        self.assertRejected(self.signed(approval_id="apr_0000000000"), "unknown_approval")

    def test_wrong_nonce(self):
        self.assertRejected(self.signed(nonce="0" * 32), "bad_nonce")

    def test_fingerprint_mismatch_when_args_differ(self):
        fp = egress.args_fingerprint(SECRET, "run_sql", {"query": "DROP TABLE users"})
        self.assertRejected(self.signed(args_fingerprint=fp), "fingerprint_mismatch")

    def test_validly_signed_decision_for_another_gateways_secret(self):
        fp = egress.args_fingerprint(bytes.fromhex("22" * 32), "run_sql", ARGS)
        self.assertRejected(self.signed(args_fingerprint=fp), "fingerprint_mismatch")

    # ---- freshness ----
    def test_expired(self):
        self.assertRejected(self.signed(decided_at=(self.now - timedelta(minutes=30)).strftime(FMT),
                                        valid_until=(self.now - timedelta(minutes=1)).strftime(FMT)), "expired")

    def test_future_dated(self):
        self.assertRejected(self.signed(decided_at=(self.now + timedelta(hours=2)).strftime(FMT),
                                        valid_until=(self.now + timedelta(hours=2, minutes=5)).strftime(FMT)), "future_dated")

    def test_validity_window_too_long(self):
        self.assertRejected(self.signed(valid_until=(self.now + timedelta(days=30)).strftime(FMT)), "validity_too_long")

    # ---- who may approve is decided LOCALLY, even for a validly signed decision ----
    def test_unknown_approver(self):
        self.assertRejected(self.signed(approver_ref=egress.opaque_ref(SECRET, "user", "user_999")), "unknown_approver")

    def test_requester_cannot_approve_even_with_a_valid_signature(self):
        res = self.process(self.signed(approver_ref=egress.opaque_ref(SECRET, "user", "user_482")))
        self.assertEqual((res["outcome"], res["code"]), ("refused", "local_403"))
        self.assertEqual(self.engine.get(self.appr["approval_id"])["status"], "PENDING")

    def test_non_routed_admin_cannot_approve(self):
        res = self.process(self.signed(approver_ref=egress.opaque_ref(SECRET, "user", "user_900")))
        self.assertEqual((res["outcome"], res["code"]), ("refused", "local_403"))

    def test_replay_of_a_valid_decision_does_nothing_new(self):
        msg = self.signed()
        self.assertEqual(self.process(msg)["outcome"], "applied")
        res = self.process(msg)
        self.assertEqual((res["outcome"], res["code"]), ("refused", "local_409"))

    def test_schema_garbage(self):
        for junk in (None, [], "x", {}, {**self.signed(), "extra": 1}):
            res = self.process(junk)
            self.assertEqual(res["outcome"], "rejected")


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


class FakeClient:
    def __init__(self):
        self.posts, self.gets, self.queue, self.fail = [], [], [], False

    async def post(self, url, json=None, headers=None, timeout=None):
        if self.fail:
            raise ConnectionError("boom CANARY-9f3a")
        self.posts.append((url, json, headers))
        return FakeResponse(202)

    async def get(self, url, params=None, headers=None, timeout=None):
        self.gets.append((url, params, headers))
        if self.fail:
            raise ConnectionError("boom CANARY-9f3a")
        return FakeResponse(200, {"decisions": self.queue}) if self.queue else FakeResponse(204)


class AgentTests(unittest.TestCase):
    def make(self, client=None, **kw):
        _, pub = generate()
        self.logs = []
        return CloudAgent(client or FakeClient(), base_url="https://cloud.example.com", gateway_id=GW, gateway_key="gk_secret",
                          secret=SECRET, pinned_keys=load_pinned_keys(f"k1:{pub}"), log=self.logs.append, **kw)

    APPROVAL = {"approval_id": "apr_ff4a424119", "created_at": "2026-10-28T09:14:07+00:00", "expires_at": "2026-10-28T09:29:07+00:00",
                "requester_id": "user_482", "manager_id": "user_101", "tool_name": "run_sql", "arguments": ARGS}

    def test_submit_sends_only_validated_metadata(self):
        client = FakeClient()
        agent = self.make(client)
        self.assertTrue(asyncio.run(agent.submit_approval(self.APPROVAL, VERDICT)))
        url, body, headers = client.posts[0]
        self.assertEqual(url, "https://cloud.example.com/v1/gateway/approvals")
        self.assertEqual(headers["Authorization"], "Bearer gk_secret")
        for secret_bit in ("FROM", "test_data", "quarter", "Q2", "WHERE q"):      # the statement itself must not travel
            self.assertNotIn(secret_bit, str(body))
        self.assertEqual(body["action"]["blast"]["statement_type"], "DELETE")      # only its coarse shape does

    def test_never_sends_an_invalid_message(self):
        client = FakeClient()
        agent = self.make(client)
        bad = {**self.APPROVAL, "approval_id": "apr_CANARY-9f3a"}
        self.assertFalse(asyncio.run(agent.submit_approval(bad, VERDICT)))
        self.assertEqual(client.posts, [])
        self.assertFalse(any("CANARY" in line for line in self.logs))

    def test_network_failure_is_contained_and_logs_no_content(self):
        client = FakeClient()
        client.fail = True
        agent = self.make(client)
        self.assertFalse(asyncio.run(agent.submit_approval(self.APPROVAL, VERDICT)))
        self.assertFalse(any("CANARY" in line for line in self.logs))

    def test_config_is_fail_closed(self):
        _, pub = generate()
        keys = load_pinned_keys(f"k1:{pub}")
        with self.assertRaises(ValueError):
            CloudAgent(FakeClient(), base_url="http://cloud.example.com", gateway_id=GW, gateway_key="k", secret=SECRET, pinned_keys=keys)
        with self.assertRaises(ValueError):
            CloudAgent(FakeClient(), base_url="https://cloud.example.com", gateway_id=GW, gateway_key="k", secret=SECRET, pinned_keys={})
        CloudAgent(FakeClient(), base_url="http://localhost:9000", gateway_id=GW, gateway_key="k", secret=SECRET, pinned_keys=keys, allow_insecure_localhost=True)
        with self.assertRaises(ValueError):
            CloudAgent(FakeClient(), base_url="http://evil.example.com", gateway_id=GW, gateway_key="k", secret=SECRET, pinned_keys=keys, allow_insecure_localhost=True)
        with self.assertRaises(ValueError):
            load_pinned_keys("")

    def test_poll_loop_processes_acks_and_survives_errors(self):
        client = FakeClient()
        client.queue = [{"approval_id": "apr_ff4a424119", "x": 1}]
        agent = self.make(client)
        seen = []

        def process(msg):
            seen.append(msg)
            return {"outcome": "rejected", "code": "schema", "approval_id": "apr_ff4a424119", "decision": None, "approver_user_id": None}

        async def go():
            stop = asyncio.Event()
            task = asyncio.create_task(agent.run(process, stop, wait=1))
            await asyncio.sleep(0.05)
            stop.set()
            client.queue = []
            await asyncio.wait_for(task, 3)

        asyncio.run(go())
        self.assertGreaterEqual(len(seen), 1)
        self.assertTrue(any(u.endswith("/decisions/ack") for u, _, _ in client.posts))
        ack = next(b for u, b, _ in client.posts if u.endswith("/decisions/ack"))
        self.assertEqual(set(ack), {"schema", "approval_id", "outcome", "code"})

        client.fail = True
        async def failing():
            stop = asyncio.Event()
            task = asyncio.create_task(agent.run(process, stop, wait=1))
            await asyncio.sleep(0.05)
            stop.set()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        asyncio.run(failing())
        self.assertTrue(any("poll failed" in l for l in self.logs))
        self.assertFalse(any("CANARY" in l for l in self.logs))


if __name__ == "__main__":
    unittest.main()
