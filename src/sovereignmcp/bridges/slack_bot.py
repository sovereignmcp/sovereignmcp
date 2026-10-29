# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""SovereignMCP Slack approval bot (Socket Mode).

Secrets come from environment variables, never from this file:
  SLACK_BOT_TOKEN, SLACK_APP_TOKEN, SOVEREIGN_BRIDGE_TOKEN   (optional: SOVEREIGN_GATEWAY)
"""
import os
import re
import sys

import requests
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler


def need(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"Missing environment variable {name}")
    return value


SLACK_BOT_TOKEN = need("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN = need("SLACK_APP_TOKEN")
BRIDGE_TOKEN = need("SOVEREIGN_BRIDGE_TOKEN")
GATEWAY_URL = os.environ.get("SOVEREIGN_GATEWAY", "http://127.0.0.1:8000")
APPROVAL_ID = re.compile(r"^apr_[0-9a-f]{10}$")

app = App(token=SLACK_BOT_TOKEN)


def decide(approval_id: str, decision: str, slack_user_id: str):
    """Ask the gateway to record the decision as the person who clicked. Returns (ok, detail)."""
    if not APPROVAL_ID.match(approval_id or ""):
        return False, "Malformed approval id"
    try:
        r = requests.post(
            f"{GATEWAY_URL}/approvals/{approval_id}/decide-via-slack",
            json={"decision": decision, "slack_user_id": slack_user_id},
            headers={"Authorization": f"Bearer {BRIDGE_TOKEN}"},
            timeout=10,
        )
    except requests.RequestException as exc:
        return False, f"Gateway unreachable ({type(exc).__name__})"
    try:
        data = r.json()
    except ValueError:
        data = {}
    if r.status_code == 200:
        return True, data.get("status", decision)
    return False, data.get("error", f"Gateway returned HTTP {r.status_code}")


def handle(ack, body, decision: str):
    ack()
    approval_id = body["actions"][0]["value"]
    clicker = body["user"]["id"]
    channel, ts = body["channel"]["id"], body["message"]["ts"]

    ok, detail = decide(approval_id, decision, clicker)
    if not ok:
        # Do NOT touch the original message: the real approver can still decide.
        app.client.chat_postEphemeral(channel=channel, user=clicker, text=f":no_entry: Not recorded: {detail}")
        print(f"[!] refused for {clicker} on {approval_id}: {detail}", flush=True)
        return

    if decision == "APPROVED":
        text = f":white_check_mark: *Approved* by <@{clicker}>. The requester must now repeat the same call."
    else:
        text = f":no_entry_sign: *Denied* by <@{clicker}>. Nothing was executed."
    app.client.chat_update(channel=channel, ts=ts, text=text, blocks=[])
    print(f"[+] {decision} by {clicker} for {approval_id}", flush=True)


@app.action("approve_request")
def on_approve(ack, body):
    handle(ack, body, "APPROVED")


@app.action("deny_request")
def on_deny(ack, body):
    handle(ack, body, "DENIED")


if __name__ == "__main__":
    print("SovereignMCP approval bot starting (Socket Mode)...", flush=True)
    SocketModeHandler(app, SLACK_APP_TOKEN).start()
