# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Local stand-in for your control plane, for testing the hybrid flow end to end.

    pip install fastapi uvicorn cryptography
    python examples/dev_keys.py                 # once
    set MOCK_SIGNING_KEY=<private b64>          # PowerShell: $env:MOCK_SIGNING_KEY="..."
    set MOCK_GATEWAY_KEY=gk_dev_key             # what the gateway sends as its bearer credential
    uvicorn mock_cloud:app --port 9000

It prints every approval request it receives (metadata only, proving what crossed the wire),
and lets you play "approver" with:  POST /admin/decide/{approval_id}  {"decision": "APPROVED"}
"""
import asyncio
import os
import time
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sovereignmcp.cloud.contract import REQUEST_SCHEMA, SCHEMA_DECISION, ContractViolation, validate


def sign_message(message: dict, private_b64: str, kid: str) -> dict:
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    body = {**{k: v for k, v in message.items() if k not in ("sig", "kid")}, "kid": kid}
    raw = key.sign(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
    return {**body, "sig": "ed25519:" + base64.b64encode(raw).decode()}

app = FastAPI(title="Mock SovereignMCP control plane")
GATEWAY_KEY = os.environ.get("MOCK_GATEWAY_KEY", "gk_dev_key")
SIGNING_KEY = os.environ.get("MOCK_SIGNING_KEY", "")
KID = os.environ.get("MOCK_KID", "k1")
requests_seen: dict = {}      # approval_id -> the exact metadata message the gateway sent
outbox: list = []             # signed decisions waiting for the gateway to pick up


def _auth(authorization: str):
    if authorization != f"Bearer {GATEWAY_KEY}":
        raise HTTPException(401, "bad gateway credential")


@app.post("/v1/gateway/approvals")
async def receive_approval(request: Request, authorization: str = Header("")):
    _auth(authorization)
    body = await request.json()
    try:
        validate(body, REQUEST_SCHEMA)           # the cloud enforces the same closed contract
    except ContractViolation as exc:
        raise HTTPException(422, str(exc))
    if body["approval_id"] in requests_seen:
        return Response(status_code=409)
    requests_seen[body["approval_id"]] = body
    print("\n=== APPROVAL REQUEST (this is ALL the cloud ever sees) ===")
    print(body, flush=True)
    return Response(status_code=202)


@app.get("/v1/gateway/decisions")
async def poll(wait: int = 25, authorization: str = Header("")):
    _auth(authorization)
    deadline = time.monotonic() + min(wait, 30)
    while time.monotonic() < deadline:
        if outbox:
            batch = outbox[:]
            return {"decisions": batch}          # redelivered until acked
        await asyncio.sleep(0.5)
    return Response(status_code=204)


@app.post("/v1/gateway/decisions/ack")
async def ack(request: Request, authorization: str = Header("")):
    _auth(authorization)
    body = await request.json()
    outbox[:] = [d for d in outbox if d["approval_id"] != body.get("approval_id")]
    print("ack:", body, flush=True)
    return Response(status_code=204)


@app.post("/admin/decide/{approval_id}")
async def decide(approval_id: str, request: Request):
    """Pretend to be the approver clicking in your hosted inbox."""
    if not SIGNING_KEY:
        raise HTTPException(500, "set MOCK_SIGNING_KEY")
    req = requests_seen.get(approval_id)
    if not req:
        raise HTTPException(404, "unknown approval")
    body = await request.json()
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    message = {
        "schema": SCHEMA_DECISION, "gateway_id": req["gateway_id"], "approval_id": approval_id,
        "decision": body.get("decision", "DENIED"), "approver_ref": body.get("approver_ref", req["approver_ref"]),
        "args_fingerprint": req["args_fingerprint"], "decided_at": now.strftime(fmt),
        "valid_until": (now + timedelta(minutes=15)).strftime(fmt), "nonce": req["nonce"],
    }
    outbox.append(sign_message(message, SIGNING_KEY, KID))
    return JSONResponse({"queued": approval_id, "decision": message["decision"]})
