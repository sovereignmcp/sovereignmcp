"""Approval notifications. Slack incoming webhook if SLACK_WEBHOOK_URL is set, else console."""
import json
import os
from core.audit import redact

async def notify_approval(client, approval: dict) -> str:
    text = (
        f":rotating_light: *Approval needed* from {approval.get('manager_slack') or approval['manager_id']}\n"
        f"Requester: {approval['requester_name']} ({approval['requester_id']})\n"
        f"Tool: `{approval['tool_name']}`\n"
        f"Arguments: `{json.dumps(redact(approval['arguments']))}`\n"
        f"Why flagged: {approval['reason']}\n"
        f"Blast radius: {approval['blast_radius']}\n"
        f"Decide: POST /approvals/{approval['approval_id']}/decide  {{\"decision\": \"APPROVED\" | \"DENIED\"}}"
    )
    url = os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        print("\n" + "=" * 60 + "\n" + text + "\n" + "=" * 60, flush=True)
        return "console"
    try:
        r = await client.post(url, json={"text": text}, timeout=5)
        return "slack" if r.status_code < 300 else f"slack_http_{r.status_code}"
    except Exception as exc:
        print(f"[notify] slack failed: {exc}\n{text}", flush=True)
        return "slack_error"
