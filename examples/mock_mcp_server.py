# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Mock internal MCP server (port 8001). It trusts everything, which is the point of the demo.
It NEVER executes commands or fetches URLs: it only echoes what it was asked to do."""
from fastapi import FastAPI, Request
from fastapi.responses import Response

app = FastAPI(title="Vulnerable internal MCP server (demo)")

TOOLS = [
    {"name": n, "description": d, "inputSchema": {"type": "object"}}
    for n, d in [
        ("read_metrics", "Read Q3 metrics"), ("run_sql", "Run SQL on the production DB"),
        ("update_user", "Update a user's profile or role"), ("delete_database", "Wipe the production database"),
        ("run_command", "Run a shell command"), ("fetch_url", "Fetch a URL"),
    ]
]


def text(msg: str) -> dict:
    return {"content": [{"type": "text", "text": msg}], "isError": False}


@app.post("/mcp")
async def mcp(request: Request):
    body = await request.json()
    method, rid = body.get("method"), body.get("id")
    if rid is None:  # notification
        return Response(status_code=202)
    if method == "initialize":
        result = {
            "protocolVersion": (body.get("params") or {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "vulnerable-internal-mcp", "version": "0.1.0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        p = body.get("params") or {}
        name, a = p.get("name"), p.get("arguments") or {}
        replies = {
            "read_metrics": "Q3 Revenue: $4.8M | Active Orgs: 310",
            "run_sql": f"EXECUTED: {a.get('query')}",
            "update_user": f"UPDATED {a.get('target_user')} -> role={a.get('role')}",
            "delete_database": "PRODUCTION DATABASE WIPED",
            "run_command": f"WOULD RUN: {a.get('command')}",
            "fetch_url": f"WOULD FETCH: {a.get('url')}",
        }
        if name not in replies:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "Unknown tool"}}
        result = text(replies[name])
    else:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}
