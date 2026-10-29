import asyncio
import os
import unittest
from unittest import mock

from sovereignmcp.core import notify

APPROVAL = {
    "approval_id": "apr_ff4a424119", "requester_id": "user_482", "requester_name": "Rohan", "manager_id": "user_101",
    "manager_slack": "@priya", "tool_name": "run_sql", "arguments": {"query": "DELETE FROM t", "api_key": "SECRET-123"},
    "reason": "Non-read SQL needs approval", "blast_radius": "DELETE on ['t'], WHERE clause: NO (unbounded)",
}


class FakeResp:
    def __init__(self, body, status=200):
        self._b, self.status_code = body, status

    def json(self):
        return self._b


class FakeClient:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    async def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append((url, json, headers))
        return self.responses.pop(0)


def run(coro):
    return asyncio.run(coro)


class NotifyTests(unittest.TestCase):
    def test_blocks_match_the_bot_handlers_and_redact_secrets(self):
        blocks = notify.build_blocks(APPROVAL)
        buttons = blocks[1]["elements"]
        self.assertEqual([b["action_id"] for b in buttons], ["approve_request", "deny_request"])
        self.assertTrue(all(b["value"] == "apr_ff4a424119" for b in buttons))
        self.assertNotIn("SECRET-123", str(blocks))

    def test_dm_with_buttons_when_bot_token_and_slack_id_exist(self):
        client = FakeClient([FakeResp({"ok": True, "channel": {"id": "D123"}}), FakeResp({"ok": True})])
        with mock.patch.dict(os.environ, {"SLACK_BOT_TOKEN": "xoxb-test"}, clear=False):
            self.assertEqual(run(notify.notify_approval(client, APPROVAL, "U_PRIYA")), "slack_buttons")
        (open_url, open_body, open_headers), (post_url, post_body, _) = client.calls
        self.assertTrue(open_url.endswith("conversations.open"))
        self.assertEqual(open_body, {"users": "U_PRIYA"})
        self.assertEqual(open_headers["Authorization"], "Bearer xoxb-test")
        self.assertEqual(post_body["channel"], "D123")          # a DM to the manager, not a shared channel
        self.assertIn("blocks", post_body)

    def test_falls_back_to_webhook_then_console(self):
        client = FakeClient([FakeResp({"ok": False, "error": "missing_scope"}), FakeResp({}, 200)])
        env = {"SLACK_BOT_TOKEN": "xoxb-test", "SLACK_WEBHOOK_URL": "https://hooks.example/x"}
        with mock.patch.dict(os.environ, env, clear=False):
            self.assertEqual(run(notify.notify_approval(client, APPROVAL, "U_PRIYA")), "slack_webhook")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(run(notify.notify_approval(FakeClient([]), APPROVAL, None)), "console")

    def test_network_failure_never_raises(self):
        class Boom:
            async def post(self, *a, **k):
                raise ConnectionError("down")
        with mock.patch.dict(os.environ, {"SLACK_BOT_TOKEN": "xoxb-test"}, clear=False):
            self.assertEqual(run(notify.notify_approval(Boom(), APPROVAL, "U_PRIYA")), "console")


if __name__ == "__main__":
    unittest.main()
