"""Verifies decisions that arrive from the cloud. The gateway trusts NOTHING it can't check locally.

A decision is applied only if ALL of these hold:
  1. it matches the closed schema                       5. the nonce is the one this gateway derived
  2. the Ed25519 signature verifies against a PINNED key  6. the args fingerprint matches OUR stored args
  3. it is addressed to this gateway                     7. it is fresh (not expired, not future-dated)
  4. it refers to an approval this gateway created       8. the approver maps to a LOCAL user, and the
                                                            local approval engine accepts that user
                                                            (routed manager only, never the requester)
"""
import base64
import binascii
import hmac
import json
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# SECURED: Fixed internal imports to use the public namespace
from sovereignmcp.cloud import egress
from sovereignmcp.cloud.contract import DECISION_SCHEMA, ContractViolation, validate


class DecisionRejected(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical(message: dict) -> bytes:
    return json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_pinned_keys(spec: str) -> dict:
    """'kid1:BASE64PUBKEY,kid2:BASE64PUBKEY'. Several keys allow rotation."""
    keys = {}
    for item in (spec or "").split(","):
        item = item.strip()
        if not item:
            continue
        kid, _, b64 = item.partition(":")
        raw = base64.b64decode(b64, validate=True)
        if len(raw) != 32:
            raise ValueError(f"public key '{kid}' must be 32 bytes")
        keys[kid] = Ed25519PublicKey.from_public_bytes(raw)
    if not keys:
        raise ValueError("no pinned cloud public keys configured")
    return keys


def verify_signature(message: dict, keys: dict) -> None:
    kid = message.get("kid")
    if kid not in keys:
        raise DecisionRejected("unknown_kid")
    body = {k: v for k, v in message.items() if k != "sig"}     # kid is part of what is signed
    try:
        raw = base64.b64decode(message["sig"][len("ed25519:"):], validate=True)
        keys[kid].verify(raw, canonical(body))
    except (InvalidSignature, ValueError, binascii.Error, KeyError):
        raise DecisionRejected("bad_signature")


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _result(outcome, code, message, approver_user_id=None):
    aid = message.get("approval_id") if isinstance(message, dict) else None
    return {
        "outcome": outcome,                  # applied | rejected | refused
        "code": code,
        "approval_id": aid if isinstance(aid, str) and len(aid) <= 20 else None,
        "decision": message.get("decision") if isinstance(message, dict) and message.get("decision") in ("APPROVED", "DENIED") else None,
        "approver_user_id": approver_user_id,
    }


def process_decision(message, *, secret: bytes, keys: dict, gateway_id: str, get_approval, user_ids, decide,
                     now=None, max_validity_s: int = 3600, skew_s: int = 120) -> dict:
    """get_approval(id) -> local approval record or None; user_ids() -> local user ids;
    decide(approval_id, user_id, decision) -> the local ApprovalEngine.decide result."""
    now = now or datetime.now(timezone.utc)
    try:
        validate(message, DECISION_SCHEMA)
    except ContractViolation:
        return _result("rejected", "schema", message)

    try:
        verify_signature(message, keys)
        if message["gateway_id"] != gateway_id:
            raise DecisionRejected("wrong_gateway")
        approval = get_approval(message["approval_id"])
        if not approval:
            raise DecisionRejected("unknown_approval")
        if not hmac.compare_digest(message["nonce"], egress.nonce_for(secret, message["approval_id"])):
            raise DecisionRejected("bad_nonce")
        expected = egress.args_fingerprint(secret, approval["tool_name"], approval["arguments"])
        if not hmac.compare_digest(message["args_fingerprint"], expected):
            raise DecisionRejected("fingerprint_mismatch")
        decided, valid_until = _ts(message["decided_at"]), _ts(message["valid_until"])
        if decided > now + timedelta(seconds=skew_s):
            raise DecisionRejected("future_dated")
        if valid_until <= now:
            raise DecisionRejected("expired")
        if valid_until - decided > timedelta(seconds=max_validity_s):
            raise DecisionRejected("validity_too_long")
        approver_id = next((u for u in user_ids() if egress.opaque_ref(secret, "user", u) == message["approver_ref"]), None)
        if approver_id is None:
            raise DecisionRejected("unknown_approver")
    except DecisionRejected as exc:
        return _result("rejected", exc.code, message)
    except ValueError:
        return _result("rejected", "malformed_time", message)

    outcome = decide(message["approval_id"], approver_id, message["decision"])
    if "error" in outcome:                   # local engine said no: wrong manager, requester, already decided...
        return _result("refused", f"local_{outcome['code']}", message, approver_id)
    return _result("applied", "ok", message, approver_id)
```[cite: 43]