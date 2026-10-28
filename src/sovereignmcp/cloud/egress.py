"""Builds the ONLY thing the gateway may send to the cloud.

The outbound message is CONSTRUCTED field by field from enums, counts and keyed hashes (never
copied from a bigger object and filtered), then validated against the closed contract.
Secrets here (HMAC key) never leave the customer's machine.
"""
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone

# SECURED: Fixed internal import to use the public namespace
from sovereignmcp.cloud.contract import (REASON_CODES, REQUEST_SCHEMA, SCHEMA_REQUEST, STATEMENT_TYPES,
                                         ContractViolation, validate)

_PLAIN_TOOL = re.compile(r"[A-Za-z0-9_.\-]{1,64}")


def _hmac(secret: bytes, label: str, data: str) -> str:
    return hmac.new(secret, f"{label}\x00{data}".encode("utf-8"), hashlib.sha256).hexdigest()


def opaque_ref(secret: bytes, kind: str, ident: str) -> str:
    return "u_" + _hmac(secret, "ref:" + kind, str(ident))[:12]


def nonce_for(secret: bytes, approval_id: str) -> str:
    return _hmac(secret, "nonce", approval_id)[:32]


def args_fingerprint(secret: bytes, tool: str, arguments: dict) -> str:
    """KEYED hash. A plain SHA-256 of a short command like `cat /etc/shadow` can be guessed offline;
    without this key the cloud cannot test guesses."""
    canon = json.dumps({"tool": tool, "args": arguments}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "hmac-sha256:" + _hmac(secret, "args", canon)


def tool_label(secret: bytes, tool: str, mode: str = "plain") -> str:
    if mode == "plain" and _PLAIN_TOOL.fullmatch(tool or ""):
        return tool
    return "t_" + _hmac(secret, "tool", str(tool))[:12]


def to_ts(iso: str) -> str:
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- classification: our own fixed phrases in, enums out ---------------------------------------
_PHRASES = [
    ("which has side effects", "SIDE_EFFECT_FUNCTION"),
    ("side-effect function", "SIDE_EFFECT_FUNCTION"),
    ("Non-read SQL", "NON_READ_SQL"),
    ("is high-risk and needs manager approval", "TOOL_REQUIRES_APPROVAL"),
    ("Shell metacharacters", "SHELL_METACHARACTERS"),
    ("not on the allowed-command list", "COMMAND_NOT_ALLOWLISTED"),
    ("Privilege elevation", "PRIVILEGE_ELEVATION"),
    ("sensitive path", "SENSITIVE_PATH"),
    ("can write or execute", "RISKY_FLAG"),
    ("Environment-variable prefix", "ENV_PREFIX"),
    ("not a read-only subcommand", "NON_READ_SUBCOMMAND"),
    ("Sensitive service port", "SENSITIVE_PORT"),
    ("not on the allowed-host list", "HOST_NOT_ALLOWLISTED"),
    ("needs review (unknown_hosts", "UNKNOWN_HOST"),
]
_CATEGORY = {
    "NON_READ_SQL": "sql", "SIDE_EFFECT_FUNCTION": "sql",
    "SHELL_METACHARACTERS": "shell", "COMMAND_NOT_ALLOWLISTED": "shell", "PRIVILEGE_ELEVATION": "shell",
    "SENSITIVE_PATH": "shell", "RISKY_FLAG": "shell", "ENV_PREFIX": "shell", "NON_READ_SUBCOMMAND": "shell",
    "SENSITIVE_PORT": "network", "HOST_NOT_ALLOWLISTED": "network", "UNKNOWN_HOST": "network",
    "TOOL_REQUIRES_APPROVAL": "policy", "OTHER": "other",
}


def reason_code(reason: str) -> str:
    reason = reason or ""
    for phrase, code in _PHRASES:
        if phrase in reason:
            return code
    return "OTHER"


_STMT = re.compile(r"^([A-Za-z_]+) on ")
_WHERE = ", WHERE clause: "
_ITEM = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")


def parse_blast(blast: str) -> dict:
    """Coarse SQL shape only: statement type, WHERE yes/no, number of tables. Never names."""
    out = {"statement_type": None, "has_where": None, "tables_count": None}
    blast = blast or ""
    m = _STMT.match(blast)
    idx = blast.rfind(_WHERE)          # last occurrence: a table name can't spoof it
    if not m or idx < 0:
        return out
    stmt = m.group(1).upper()
    out["statement_type"] = stmt if stmt in STATEMENT_TYPES else "OTHER"
    tail = blast[idx + len(_WHERE):]
    out["has_where"] = True if tail.startswith("yes") else False if tail.startswith("NO") else None
    middle = blast[m.end():idx]
    out["tables_count"] = min(len(_ITEM.findall(middle)), 99) if middle.startswith("[") else 0
    return out


def _risk_tier(code: str, blast: dict) -> str:
    if code == "TOOL_REQUIRES_APPROVAL":
        return "policy"
    cat = _CATEGORY[code]
    if cat == "sql":
        if code == "SIDE_EFFECT_FUNCTION":
            return "execution"
        return "destructive" if blast["statement_type"] in ("DROP", "TRUNCATE", "DELETE", "ALTER") else "write"
    return {"shell": "execution", "network": "network"}.get(cat, "policy")


def build_approval_request(*, approval: dict, verdict: dict, gateway_id: str, policy_version: str,
                           secret: bytes, tool_names: str = "plain") -> dict:
    code = reason_code(verdict.get("reason", ""))
    blast = parse_blast(verdict.get("blast_radius", ""))
    message = {
        "schema": SCHEMA_REQUEST,
        "gateway_id": gateway_id,
        "approval_id": approval["approval_id"],
        "created_at": to_ts(approval["created_at"]),
        "expires_at": to_ts(approval["expires_at"]),
        "requester_ref": opaque_ref(secret, "user", approval["requester_id"]),
        "approver_ref": opaque_ref(secret, "user", approval["manager_id"]),
        "action": {
            "tool": tool_label(secret, approval["tool_name"], tool_names),
            "risk_tier": _risk_tier(code, blast),
            "category": _CATEGORY[code],
            "reason_code": code,
            "blast": blast,
        },
        "args_fingerprint": args_fingerprint(secret, approval["tool_name"], approval["arguments"]),
        "policy_version": policy_version,
        "nonce": nonce_for(secret, approval["approval_id"]),
    }
    validate(message, REQUEST_SCHEMA)
    return message


# --- local secrets / identifiers --------------------------------------------------------------
def load_egress_secret(path: str = "data/egress_secret") -> bytes:
    env = os.environ.get("SOVEREIGN_EGRESS_SECRET")
    if env:
        secret = bytes.fromhex(env)
    else:
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as f:
                f.write(os.urandom(32).hex())
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        with open(path) as f:
            secret = bytes.fromhex(f.read().strip())
    if len(secret) < 32:
        raise ValueError("egress secret must be at least 32 bytes")
    return secret


def policy_version_of(policy_path: str) -> str:
    with open(policy_path, "rb") as f:
        return "pol_" + hashlib.sha256(f.read()).hexdigest()[:12]
```[cite: 42]