# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Approval notifications, best available channel first:

  1. Slack interactive message (Approve / Deny buttons) as a DM to the routed manager
     needs SLACK_BOT_TOKEN (scopes: chat:write, im:write) and the manager's `slack_user_id` in policy.yaml;
     the buttons are handled by `python -m sovereignmcp.bridges.slack_bot`
  2. Slack incoming webhook (plain text)         SLACK_WEBHOOK_URL
  3. Console
"""
import json
import os

from sovereignmcp.core.audit import redact

SLACK_API = "https://slack.com/api"


def _text(approval: dict) -> str:
    return (
        f":rotating_light: *Approval needed* from {approval.get('manager_slack') or approval['manager_id']}\n"
        f"Requester: {approval['requester_name']} ({approval['requester_id']})\n"
        f"Tool: `{approval['tool_name']}`\n"
        f"Arguments: `{json.dumps(redact(approval['arguments']))}`\n"
        f"Why flagged: {approval['reason']}\n"
        f"Blast radius: {approval['blast_radius']}\n"
        f"Approval ID: {approval['approval_id']}"
    )


def build_blocks(approval: dict) -> list:
    aid = approval["approval_id"]
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": _text(approval)}},
        {"type": "actions", "elements": [
            {"type": "button", "style": "primary", "action_id": "approve_request", "value": aid,
             "text": {"type": "plain_text", "text": "Approve"}},
            {"type": "button", "style": "danger", "action_id": "deny_request", "value": aid,
             "text": {"type": "plain_text", "text": "Deny"}},
        ]},
    ]


async def _post_buttons(client, token: str, slack_user_id: str, approval: dict) -> str:
    headers = {"Authorization": f"Bearer {token}"}
    opened = (await client.post(f"{SLACK_API}/conversations.open", json={"users": slack_user_id},
                                headers=headers, timeout=5)).json()
    if not opened.get("ok"):
        return f"slack_error_{opened.get('error', 'open_failed')}"
    posted = (await client.post(f"{SLACK_API}/chat.postMessage", headers=headers, timeout=5, json={
        "channel": opened["channel"]["id"], "text": _text(approval), "blocks": build_blocks(approval),
    })).json()
    return "slack_buttons" if posted.get("ok") else f"slack_error_{posted.get('error', 'post_failed')}"


async def notify_approval(client, approval: dict, approver_slack_id=None) -> str:
    text = _text(approval)
    token = os.getenv("SLACK_BOT_TOKEN")
    try:
        if token and approver_slack_id:
            result = await _post_buttons(client, token, approver_slack_id, approval)
            if result == "slack_buttons":
                return result
            print(f"[notify] Slack buttons failed ({result}); falling back", flush=True)
        url = os.getenv("SLACK_WEBHOOK_URL")
        if url:
            r = await client.post(url, json={"text": text}, timeout=5)
            return "slack_webhook" if r.status_code < 300 else f"slack_http_{r.status_code}"
    except Exception as exc:
        print(f"[notify] Slack failed: {type(exc).__name__}", flush=True)
    print("\n" + "=" * 60 + "\n" + text + "\n" + "=" * 60, flush=True)
    return "console"
