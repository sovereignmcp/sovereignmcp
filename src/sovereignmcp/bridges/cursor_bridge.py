# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""stdio <-> SovereignMCP bridge for MCP clients that want a local command.

Config comes from the environment (set it in the client's "env" block):
  SOVEREIGN_TOKEN (required), SOVEREIGN_URL, SOVEREIGN_AGENT
"""
import json
import os
import sys

import requests

GATEWAY_URL = os.environ.get("SOVEREIGN_URL", "http://127.0.0.1:8000/mcp")
TOKEN = os.environ.get("SOVEREIGN_TOKEN")
AGENT = os.environ.get("SOVEREIGN_AGENT", "alpha_assistant")

session = requests.Session()
session_id = None


def send(msg: dict):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def rpc_error(rid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def handle(payload):
    global session_id
    if isinstance(payload, list):          # the gateway rejects batches, so unpack them
        for item in payload:
            handle(item)
        return
    if not isinstance(payload, dict):
        return
    is_request = "id" in payload and "method" in payload
    rid = payload.get("id")

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "X-Agent-ID": AGENT,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    try:
        r = session.post(GATEWAY_URL, json=payload, headers=headers, timeout=60)
    except requests.RequestException as exc:
        if is_request:
            send(rpc_error(rid, -32603, f"Gateway unreachable: {type(exc).__name__}"))
        return

    session_id = r.headers.get("mcp-session-id") or session_id
    if not is_request:                      # notifications and client responses get no reply
        return

    if r.status_code != 200 or "application/json" not in r.headers.get("content-type", ""):
        send(rpc_error(rid, -32603, f"Gateway HTTP {r.status_code}: {r.text[:200]}"))
        return
    try:
        data = r.json()
    except ValueError:
        send(rpc_error(rid, -32603, "Gateway returned invalid JSON"))
        return
    if not isinstance(data, dict) or data.get("jsonrpc") != "2.0":
        # e.g. {"error": "unauthorized"}: wrap it so the client gets a valid JSON-RPC message
        send(rpc_error(rid, -32603, f"Gateway error: {str(data)[:200]}"))
        return
    if data.get("id") is None:
        data["id"] = rid
    send(data)


def main():
    if not TOKEN:
        sys.stderr.write("SOVEREIGN_TOKEN is not set\n")
        sys.exit(1)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            send(rpc_error(None, -32700, "Parse error"))
            continue
        handle(payload)


if __name__ == "__main__":
    main()
