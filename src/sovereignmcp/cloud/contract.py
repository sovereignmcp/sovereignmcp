# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""The wire contract between the gateway (data plane) and the cloud (control plane).

CLOSED schemas: unknown fields, free text, wrong types, bad enums and oversize messages are
rejected. Error messages name the field path only, never the offending value, so a rejected
message can never leak its content into a log.
"""
import json
import re

SCHEMA_REQUEST = "sovereign.approval_request.v1"
SCHEMA_DECISION = "sovereign.approval_decision.v1"
SCHEMA_ACK = "sovereign.decision_ack.v1"
MAX_BYTES = 2048

RISK_TIERS = ("read", "write", "destructive", "execution", "network", "policy")
CATEGORIES = ("sql", "shell", "network", "policy", "other")
REASON_CODES = (
    "NON_READ_SQL", "SIDE_EFFECT_FUNCTION", "TOOL_REQUIRES_APPROVAL", "SHELL_METACHARACTERS",
    "COMMAND_NOT_ALLOWLISTED", "PRIVILEGE_ELEVATION", "SENSITIVE_PATH", "RISKY_FLAG", "ENV_PREFIX",
    "NON_READ_SUBCOMMAND", "SENSITIVE_PORT", "HOST_NOT_ALLOWLISTED", "UNKNOWN_HOST", "OTHER",
)
STATEMENT_TYPES = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "MERGE", "OTHER")

TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
REF = r"u_[0-9a-f]{12}"
FINGERPRINT = r"hmac-sha256:[0-9a-f]{64}"


class ContractViolation(Exception):
    pass


def S(pattern=None, enum=None, nullable=False, max_len=128):
    return {"type": "string", "pattern": pattern, "enum": enum, "nullable": nullable, "max_len": max_len}


def I(lo, hi, nullable=False):
    return {"type": "integer", "lo": lo, "hi": hi, "nullable": nullable}


def B(nullable=False):
    return {"type": "boolean", "nullable": nullable}


def O(properties, nullable=False):
    return {"type": "object", "properties": properties, "required": list(properties), "nullable": nullable}


REQUEST_SCHEMA = O({
    "schema": S(enum=[SCHEMA_REQUEST]),
    "gateway_id": S(r"gw_[a-z0-9]{4,32}"),
    "approval_id": S(r"apr_[0-9a-f]{10}"),
    "created_at": S(TS),
    "expires_at": S(TS),
    "requester_ref": S(REF),
    "approver_ref": S(REF),
    "action": O({
        "tool": S(r"[A-Za-z0-9_.\-]{1,64}|t_[0-9a-f]{12}"),
        "risk_tier": S(enum=list(RISK_TIERS)),
        "category": S(enum=list(CATEGORIES)),
        "reason_code": S(enum=list(REASON_CODES)),
        "blast": O({
            "statement_type": S(enum=list(STATEMENT_TYPES), nullable=True),
            "has_where": B(nullable=True),
            "tables_count": I(0, 99, nullable=True),
        }),
    }),
    "args_fingerprint": S(FINGERPRINT),
    "policy_version": S(r"[A-Za-z0-9._\-]{1,40}"),
    "nonce": S(r"[0-9a-f]{32}"),
})

DECISION_SCHEMA = O({
    "schema": S(enum=[SCHEMA_DECISION]),
    "gateway_id": S(r"gw_[a-z0-9]{4,32}"),
    "approval_id": S(r"apr_[0-9a-f]{10}"),
    "decision": S(enum=["APPROVED", "DENIED"]),
    "approver_ref": S(REF),
    "args_fingerprint": S(FINGERPRINT),
    "decided_at": S(TS),
    "valid_until": S(TS),
    "nonce": S(r"[0-9a-f]{32}"),
    "kid": S(r"[A-Za-z0-9_\-]{1,32}"),
    "sig": S(r"ed25519:[A-Za-z0-9+/]{86}==", max_len=100),
})

ACK_SCHEMA = O({
    "schema": S(enum=[SCHEMA_ACK]),
    "approval_id": S(r"apr_[0-9a-f]{10}"),
    "outcome": S(enum=["applied", "rejected", "refused"]),
    "code": S(r"[a-z0-9_]{1,40}"),
})


def _check(value, schema, path):
    if value is None:
        if schema.get("nullable"):
            return
        raise ContractViolation(f"{path}: null not allowed")
    kind = schema["type"]
    if kind == "object":
        if not isinstance(value, dict):
            raise ContractViolation(f"{path}: expected object")
        extra = set(value) - set(schema["properties"])
        if extra:
            raise ContractViolation(f"{path}: unexpected field(s) {sorted(str(k)[:20] for k in extra)}")
        missing = [k for k in schema["required"] if k not in value]
        if missing:
            raise ContractViolation(f"{path}: missing field(s) {missing}")
        for key, sub in schema["properties"].items():
            _check(value[key], sub, f"{path}.{key}")
    elif kind == "string":
        if not isinstance(value, str):
            raise ContractViolation(f"{path}: expected string")
        if len(value) > schema["max_len"]:
            raise ContractViolation(f"{path}: too long")
        if schema["enum"] is not None and value not in schema["enum"]:
            raise ContractViolation(f"{path}: not an allowed value")
        if schema["pattern"] is not None and not re.fullmatch(schema["pattern"], value):
            raise ContractViolation(f"{path}: wrong format")
    elif kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ContractViolation(f"{path}: expected integer")
        if not schema["lo"] <= value <= schema["hi"]:
            raise ContractViolation(f"{path}: out of range")
    elif kind == "boolean":
        if not isinstance(value, bool):
            raise ContractViolation(f"{path}: expected boolean")


def validate(message, schema, max_bytes=MAX_BYTES):
    if not isinstance(message, dict):
        raise ContractViolation("message: expected object")
    try:
        size = len(json.dumps(message, ensure_ascii=True))
    except (TypeError, ValueError):
        raise ContractViolation("message: not serializable")
    if size > max_bytes:
        raise ContractViolation("message: too large")
    _check(message, schema, "message")
