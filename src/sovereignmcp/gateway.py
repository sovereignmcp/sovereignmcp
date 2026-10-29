# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""SovereignMCP: zero-trust gateway between an AI assistant and an internal MCP server."""
import asyncio
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from sovereignmcp.core.approvals import ApprovalEngine
from sovereignmcp.core.audit import AuditVault
from sovereignmcp.core.identity import AuthError, IdentityEngine
from sovereignmcp.core.notify import notify_approval
from sovereignmcp.plugins.inspector import PayloadInspector

POLICY_PATH = os.getenv("SOVEREIGN_POLICY", "policy.yaml")
DB_PATH = os.getenv("SOVEREIGN_DB", "sovereign_audit.db")

identity = IdentityEngine(POLICY_PATH)
audit = AuditVault(DB_PATH)
approvals = ApprovalEngine(DB_PATH)

FORWARD_HEADERS = ("content-type", "accept", "mcp-session-id", "mcp-protocol-version")
client: httpx.AsyncClient
cloud_agent = None          # set only when SOVEREIGN_CLOUD_URL is configured
cloud_secret = None
_background: set = set()    # keeps fire-and-forget tasks alive


def process_cloud_decision(message: dict) -> dict:
    """Runs in a worker thread. Verifies the cloud's signed decision; the LOCAL engine has the final say."""
    from sovereignmcp.cloud.verify import process_decision

    result = process_decision(
        message, secret=cloud_secret, keys=cloud_agent.keys, gateway_id=cloud_agent.gateway_id,
        get_approval=approvals.get, user_ids=identity.user_ids,
        decide=lambda aid, uid, decision: approvals.decide(aid, uid, decision, identity.approval_ttl),
    )
    label = {"applied": f"CLOUD_{result['decision']}", "rejected": "CLOUD_REJECTED", "refused": "CLOUD_REFUSED"}[result["outcome"]]
    audit.log_event(result.get("approver_user_id") or "cloud", "cloud-approval", "cloud-agent", "approval/decide",
                    "-", {"approval_id": result.get("approval_id")}, label, f"code={result['code']}")
    return result


@asynccontextmanager
async def lifespan(_app):
    global client, cloud_agent, cloud_secret
    client = httpx.AsyncClient(timeout=60)
    stop, task = asyncio.Event(), None
    if os.getenv("SOVEREIGN_CLOUD_URL"):          # optional hybrid mode (outbound-only)
        from sovereignmcp.cloud.agent import CloudAgent
        from sovereignmcp.cloud.egress import load_egress_secret, policy_version_of
        from sovereignmcp.cloud.verify import load_pinned_keys

        cloud_secret = load_egress_secret(os.path.join(os.path.dirname(DB_PATH) or ".", "egress_secret"))
        cloud_agent = CloudAgent(
            client, base_url=os.environ["SOVEREIGN_CLOUD_URL"], gateway_id=os.environ["SOVEREIGN_GATEWAY_ID"],
            gateway_key=os.environ["SOVEREIGN_GATEWAY_KEY"], secret=cloud_secret,
            pinned_keys=load_pinned_keys(os.environ["SOVEREIGN_CLOUD_PUBKEYS"]),
            tool_names=os.getenv("SOVEREIGN_TOOL_NAMES", "plain"), policy_version=policy_version_of(POLICY_PATH),
            allow_insecure_localhost=os.getenv("SOVEREIGN_CLOUD_INSECURE_LOCALHOST") == "1",
        )
        task = asyncio.create_task(cloud_agent.run(process_cloud_decision, stop))
    yield
    stop.set()
    if task:
        task.cancel()
    await client.aclose()


app = FastAPI(title="SovereignMCP Gateway", lifespan=lifespan)


@app.exception_handler(AuthError)
async def auth_error_handler(_request: Request, exc: AuthError):
    return JSONResponse({"error": exc.detail}, status_code=exc.status)


# ---------------------------------------------------------------- helpers
async def alog(ctx, method, tool, args, decision, reason):
    # Logged BEFORE any action is forwarded: if auditing fails, the call fails closed.
    await asyncio.to_thread(
        audit.log_event, ctx["user_id"], ctx["user_name"], ctx["agent_id"], method, tool, args, decision, reason
    )


def rpc_error(req_id, code, message):
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def tool_text(req_id, text, is_error=True):
    return JSONResponse(
        {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}], "isError": is_error}}
    )


async def call_upstream(request: Request, ctx: dict, body: dict) -> httpx.Response:
    headers = {k: v for k, v in request.headers.items() if k.lower() in FORWARD_HEADERS}
    headers["x-sovereign-user"] = ctx["user_id"]
    headers["x-sovereign-agent"] = ctx["agent_id"]
    return await client.post(identity.upstream_url, json=body, headers=headers)


def relay(r: httpx.Response) -> Response:
    headers = {k: v for k, v in r.headers.items() if k.lower() == "mcp-session-id"}
    return Response(content=r.content, status_code=r.status_code, media_type=r.headers.get("content-type"), headers=headers)


# ---------------------------------------------------------------- MCP endpoint
@app.post("/mcp")
async def mcp_gateway(request: Request):
    ctx = identity.authenticate(request.headers)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if not isinstance(body, dict):  # JSON-RPC batches: fail closed for now
        return JSONResponse({"error": "batch requests are not supported"}, status_code=400)

    method = body.get("method", "")
    try:
        if method == "tools/call":
            return await handle_tools_call(request, ctx, body)
        if method == "tools/list":
            return await handle_tools_list(request, ctx, body)
        # initialize, ping, notifications, etc. pass straight through (session header preserved)
        return relay(await call_upstream(request, ctx, body))
    except httpx.HTTPError as exc:
        return rpc_error(body.get("id"), -32000, f"Upstream MCP server unreachable: {type(exc).__name__}")


@app.get("/mcp")
async def mcp_get():
    return Response(status_code=405)  # no server-initiated stream through the gateway (yet)


async def handle_tools_list(request, ctx, body):
    r = await call_upstream(request, ctx, body)
    if "application/json" not in r.headers.get("content-type", ""):
        if ctx["shadow_mode"]:
            return relay(r)
        return rpc_error(body.get("id"), -32003, "Upstream streamed a tools/list reply; cannot filter it safely")
    data = r.json()
    tools = (data.get("result") or {}).get("tools")
    if tools is None:
        return relay(r)
    visible = tools if ctx["shadow_mode"] else [t for t in tools if identity.permits(ctx, t.get("name", ""))]
    data["result"]["tools"] = visible
    await alog(ctx, "tools/list", "tools/list", {}, "ALLOWED", f"Showing {len(visible)} of {len(tools)} tools")
    return JSONResponse(data, status_code=r.status_code,
                        headers={k: v for k, v in r.headers.items() if k.lower() == "mcp-session-id"})


async def handle_tools_call(request, ctx, body):
    req_id = body.get("id")
    params = body.get("params") or {}
    tool = params.get("name")
    args = params.get("arguments") or {}
    shadow = ctx["shadow_mode"]
    if not isinstance(tool, str) or not tool or not isinstance(args, dict):
        await alog(ctx, "tools/call", str(tool), {}, "BLOCKED", "Malformed tools/call")
        return rpc_error(req_id, -32602, "Malformed tools/call")

    final_reason = "Passed all checks"

    # A. Intersection Rule, enforced on every call (hiding in tools/list is not enough)
    if not identity.permits(ctx, tool):
        reason = f"'{tool}' is outside the intersection of {ctx['user_name']}'s role and agent {ctx['agent_id']}"
        if not shadow:
            await alog(ctx, "tools/call", tool, args, "BLOCKED", reason)
            return rpc_error(req_id, -32001, f"Access denied: {reason}")
        await alog(ctx, "tools/call", tool, args, "SHADOW_WOULD_BLOCK", reason)

    # B. Deep parameter inspection
    verdict = PayloadInspector.inspect(tool, args, ctx["tool_rules"], ctx["sql_dialect"])
    if verdict["action"] == "deny":
        if not shadow:
            await alog(ctx, "tools/call", tool, args, "BLOCKED", verdict["reason"])
            return rpc_error(req_id, -32002, f"Blocked by inspection: {verdict['reason']}")
        await alog(ctx, "tools/call", tool, args, "SHADOW_WOULD_BLOCK", verdict["reason"])

    elif verdict["action"] == "approve":
        if shadow:
            await alog(ctx, "tools/call", tool, args, "SHADOW_WOULD_REQUIRE_APPROVAL", verdict["reason"])
        elif not ctx["manager_id"]:
            await alog(ctx, "tools/call", tool, args, "BLOCKED", "Needs approval but no manager is configured")
            return rpc_error(req_id, -32004, "Needs approval, but no approver is configured for this user")
        else:
            res = await asyncio.to_thread(
                approvals.request_or_resume, ctx["user_id"], ctx["user_name"], ctx["manager_id"], ctx["manager_slack"],
                tool, args, verdict["reason"], verdict["blast_radius"], ctx["approval_ttl"],
            )
            apr = res["approval"]
            outcome = res["outcome"]
            if outcome == "created":
                await alog(ctx, "tools/call", tool, args, "PENDING_APPROVAL", f"{verdict['reason']} -> {apr['approval_id']}")
                await notify_approval(client, apr, identity.slack_id_of(ctx["manager_id"]))
                if cloud_agent:       # metadata-only copy to the control plane; never blocks the local flow
                    task = asyncio.create_task(cloud_agent.submit_approval(apr, verdict))
                    _background.add(task)
                    task.add_done_callback(_background.discard)
            if outcome in ("created", "pending"):
                return tool_text(
                    req_id,
                    f"NOT EXECUTED. '{tool}' needs approval from {ctx['manager_name']} "
                    f"(approval {apr['approval_id']}). After approval, repeat this exact call to run it.",
                )
            if outcome == "denied":
                await alog(ctx, "tools/call", tool, args, "DENIED_BY_MANAGER", apr["approval_id"])
                return tool_text(req_id, f"NOT EXECUTED. {ctx['manager_name']} denied this request ({apr['approval_id']}).")
            final_reason = f"Executing with approval {apr['approval_id']} (decided by {apr['decided_by']})"

    # C. Log first, then forward
    await alog(ctx, "tools/call", tool, args, "ALLOWED", final_reason if verdict["action"] != "allow" else verdict["reason"])
    return relay(await call_upstream(request, ctx, body))


# ---------------------------------------------------------------- approvals
@app.get("/approvals/pending")
async def pending(request: Request):
    ctx = identity.authenticate(request.headers)
    return {"pending": await asyncio.to_thread(approvals.pending_for, ctx["user_id"])}


@app.get("/approvals/{approval_id}")
async def approval_status(approval_id: str, request: Request):
    ctx = identity.authenticate(request.headers)
    rec = await asyncio.to_thread(approvals.get, approval_id)
    if not rec or ctx["user_id"] not in (rec["requester_id"], rec["manager_id"]):
        return JSONResponse({"error": "approval not found"}, status_code=404)
    return rec


@app.post("/approvals/{approval_id}/decide")
async def decide(approval_id: str, request: Request):
    ctx = identity.authenticate(request.headers)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    res = await asyncio.to_thread(approvals.decide, approval_id, ctx["user_id"], body.get("decision", ""), ctx["approval_ttl"])
    if "error" in res:
        return JSONResponse({"error": res["error"]}, status_code=res["code"])
    await alog(ctx, "approval/decide", res["tool_name"], res["arguments"], res["status"],
               f"{ctx['user_name']} decided {approval_id} for requester {res['requester_id']}")
    note = "The requester must repeat the identical tool call to execute it." if res["status"] == "APPROVED" else "Denied."
    return {"approval_id": approval_id, "status": res["status"], "note": note}


@app.post("/approvals/{approval_id}/decide-via-slack")
async def decide_via_slack(approval_id: str, request: Request):
    """Used only by the Slack bot, with its own credential. The gateway maps the Slack user ID to a person,
    and the approval engine enforces 'only the routed manager, never the requester'."""
    identity.authenticate_bridge(request.headers)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    slack_id = body.get("slack_user_id")
    bridge = {"agent_id": "slack-bridge"}
    approver = identity.user_by_slack_id(slack_id)
    if not approver:
        await alog({**bridge, "user_id": f"slack:{slack_id}", "user_name": "unregistered"}, "approval/decide", "-",
                   {"approval_id": approval_id}, "REFUSED", "Slack user is not a registered approver")
        return JSONResponse({"error": "This Slack user is not a registered approver"}, status_code=403)

    actor = {**bridge, "user_id": approver["id"], "user_name": approver["name"]}
    res = await asyncio.to_thread(approvals.decide, approval_id, approver["id"], body.get("decision", ""), identity.approval_ttl)
    if "error" in res:
        await alog(actor, "approval/decide", "-", {"approval_id": approval_id}, "REFUSED", res["error"])
        return JSONResponse({"error": res["error"]}, status_code=res["code"])
    await alog(actor, "approval/decide", res["tool_name"], res["arguments"], res["status"],
               f"{approver['name']} decided {approval_id} via Slack for requester {res['requester_id']}")
    return {"approval_id": approval_id, "status": res["status"], "decided_by": approver["name"]}


# ---------------------------------------------------------------- audit + health
def _require_audit_role(ctx):
    if ctx["role"] not in ctx["audit_roles"]:
        raise AuthError(403, "Your role may not read audit data")


@app.get("/audit/verify")
async def audit_verify(request: Request):
    ctx = identity.authenticate(request.headers)
    _require_audit_role(ctx)
    return await asyncio.to_thread(audit.verify_chain)


@app.get("/healthz")
async def healthz():
    return {"ok": True}
