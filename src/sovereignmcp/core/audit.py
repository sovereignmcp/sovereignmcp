"""Tamper-evident audit log: hash-chained rows, optionally HMAC-keyed."""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone

GENESIS = "0" * 64
SENSITIVE = ("password", "secret", "token", "api_key", "apikey", "authorization", "credit_card", "ssn")

def redact(obj):
    if isinstance(obj, dict):
        return {
            k: "***REDACTED***" if any(s in str(k).lower() for s in SENSITIVE) else redact(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(i) for i in obj]
    return obj

class AuditVault:
    def __init__(self, db_path: str = "sovereign_audit.db", key=None):
        self.db_path = db_path
        k = key if key is not None else os.getenv("SOVEREIGN_AUDIT_KEY")
        self.key = k.encode() if k else None
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, user_id TEXT NOT NULL, user_name TEXT NOT NULL,
                    agent_id TEXT NOT NULL, method TEXT NOT NULL, tool_name TEXT NOT NULL,
                    arguments TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL,
                    prev_hash TEXT NOT NULL, row_hash TEXT NOT NULL)"""
            )

    def _digest(self, fields: list) -> str:
        data = json.dumps(fields, separators=(",", ":"), ensure_ascii=True).encode()
        if self.key:
            return hmac.new(self.key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def log_event(self, user_id, user_name, agent_id, method, tool_name, arguments, decision, reason) -> dict:
        args_json = json.dumps(redact(arguments), sort_keys=True)
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                last = conn.execute("SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
                prev = last["row_hash"] if last else GENESIS
                row_hash = self._digest(
                    [ts, user_id, user_name, agent_id, method, tool_name, args_json, decision, reason, prev]
                )
                conn.execute(
                    """INSERT INTO audit_logs (timestamp,user_id,user_name,agent_id,method,tool_name,
                       arguments,decision,reason,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (ts, user_id, user_name, agent_id, method, tool_name, args_json, decision, reason, prev, row_hash),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return {"row_hash": row_hash, "prev_hash": prev, "timestamp": ts}

    def verify_chain(self) -> dict:
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
        expected_prev = GENESIS
        for r in rows:
            if r["prev_hash"] != expected_prev:
                return {"valid": False, "corrupted_id": r["id"], "error": "Broken previous-hash link"}
            fields = [r["timestamp"], r["user_id"], r["user_name"], r["agent_id"], r["method"],
                      r["tool_name"], r["arguments"], r["decision"], r["reason"], r["prev_hash"]]
            if self._digest(fields) != r["row_hash"]:
                return {"valid": False, "corrupted_id": r["id"], "error": "Row data changed after write"}
            expected_prev = r["row_hash"]
        return {
            "valid": True,
            "verified_rows": len(rows),
            "head_hash": expected_prev,
            "keyed": self.key is not None,
            "note": "Export head_hash somewhere off this machine; deleting the newest rows is only detectable against an external copy."
            + ("" if self.key else " Set SOVEREIGN_AUDIT_KEY so rows can't be re-forged by someone with file access."),
        }
```[cite: 31]

***

### 2. `identity.py`
```python
"""Header identity + the Intersection Rule (human permissions AND agent permissions)."""
import fnmatch
import hashlib
import hmac
import os

import yaml

class AuthError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail

def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def _match(name: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns or [])

class IdentityEngine:
    def __init__(self, policy_path: str = "policy.yaml"):
        self.policy_path = policy_path
        self._mtime = None
        self._policy: dict = {}
        self._by_hash: dict = {}
        self._by_id: dict = {}
        self._by_slack: dict = {}
        self._load(initial=True)

    def _load(self, initial: bool = False):
        try:
            mtime = os.path.getmtime(self.policy_path)
            if mtime == self._mtime:
                return
            with open(self.policy_path, "r") as f:
                policy = yaml.safe_load(f) or {}
            users = policy.get("users", [])
            self._by_hash = {u["token_sha256"].lower(): u for u in users}
            self._by_id = {u["id"]: u for u in users}
            self._by_slack = {u["slack_user_id"]: u for u in users if u.get("slack_user_id")}
            self._policy = policy
            self._mtime = mtime
        except Exception as exc:  
            if initial:
                raise
            print(f"[policy] reload failed, keeping previous policy: {exc}", flush=True)

    @property
    def upstream_url(self) -> str:
        return os.getenv("SOVEREIGN_UPSTREAM") or self._policy.get("upstream_url", "http://127.0.0.1:8001/mcp")

    @property
    def shadow_mode(self) -> bool:
        if os.getenv("SOVEREIGN_SHADOW") is not None:
            return os.getenv("SOVEREIGN_SHADOW", "").lower() in ("1", "true", "yes")
        return bool(self._policy.get("shadow_mode", False))

    @property
    def approval_ttl(self) -> int:
        return int(self._policy.get("approval_ttl_minutes", 15))

    def authenticate_bridge(self, headers) -> None:
        """The Slack bot has its OWN credential. It may only call decide-via-slack."""
        self._load()
        expected = ((self._policy.get("approval_bridge") or {}).get("token_sha256") or "").lower()
        auth = headers.get("authorization", "")
        if not expected or not auth.lower().startswith("bearer "):
            raise AuthError(401, "Missing bridge credential")
        if not hmac.compare_digest(sha256_hex(auth[7:].strip()), expected):
            raise AuthError(403, "Invalid bridge credential")

    def user_by_slack_id(self, slack_user_id):
        self._load()
        if not isinstance(slack_user_id, str) or not slack_user_id:
            return None
        return self._by_slack.get(slack_user_id)

    def authenticate(self, headers) -> dict:
        """headers: any mapping with lowercase keys (Starlette headers work)."""
        self._load()
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise AuthError(401, "Missing bearer token")
        user = self._by_hash.get(sha256_hex(auth[7:].strip()))
        if not user:
            raise AuthError(403, "Unknown identity token")

        agent_id = headers.get("x-agent-id") or self._policy.get("default_agent", "alpha_assistant")
        agent = self._policy.get("agents", {}).get(agent_id)
        if agent is None:
            raise AuthError(403, f"Unregistered agent: {agent_id}")

        manager = self._by_id.get(user.get("manager")) or {}
        return {
            "user_id": user["id"],
            "user_name": user["name"],
            "role": user["role"],
            "manager_id": manager.get("id"),
            "manager_name": manager.get("name"),
            "manager_slack": manager.get("slack"),
            "agent_id": agent_id,
            "user_tools": user.get("allowed_tools", []),
            "agent_tools": agent.get("allowed_tools", []),
            "shadow_mode": self.shadow_mode,
            "tool_rules": self._policy.get("tool_rules", {}),
            "sql_dialect": self._policy.get("sql_dialect"),
            "approval_ttl": int(self._policy.get("approval_ttl_minutes", 15)),
            "audit_roles": self._policy.get("audit_roles", ["manager", "admin"]),
        }

    @staticmethod
    def permits(ctx: dict, tool: str) -> bool:
        """Intersection Rule: allowed only if the human's role AND the agent both allow it."""
        return _match(tool, ctx["user_tools"]) and _match(tool, ctx["agent_tools"])

    def user_ids(self):
        """Returns a list of local user IDs for the cloud verify engine."""
        self._load()
        return list(self._by_id)
```[cite: 32]

***

### 3. `notify.py`
```python
"""Approval notifications. Slack incoming webhook if SLACK_WEBHOOK_URL is set, else console."""
import json
import os
# SECURED: Fixed internal import to use public namespace
from sovereignmcp.core.audit import redact

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
```[cite: 33]

***

### 4. `__init__.py`
*(Just copy this empty file to maintain the Python module structure)*
```python

```[cite: 34]

***

### 5. `approvals.py`
```python
"""Async approval state machine. Never parks an HTTP connection."""
import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone

def _now() -> datetime:
    return datetime.now(timezone.utc)

def args_hash(arguments: dict) -> str:
    canon = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()

class ApprovalEngine:
    def __init__(self, db_path: str = "sovereign_audit.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        with closing(self._connect()) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS pending_approvals (
                    approval_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                    requester_id TEXT NOT NULL, requester_name TEXT NOT NULL,
                    manager_id TEXT NOT NULL, manager_slack TEXT,
                    tool_name TEXT NOT NULL, args_hash TEXT NOT NULL, arguments TEXT NOT NULL,
                    reason TEXT NOT NULL, blast_radius TEXT NOT NULL, status TEXT NOT NULL,
                    decided_by TEXT, decided_at TEXT, consumed_at TEXT)"""
            )

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _expired(row) -> bool:
        return datetime.fromisoformat(row["expires_at"]) <= _now()

    @staticmethod
    def _public(row) -> dict:
        d = dict(row)
        d["arguments"] = json.loads(d["arguments"])
        return d

    def request_or_resume(self, requester_id, requester_name, manager_id, manager_slack,
                          tool_name, arguments, reason, blast_radius, ttl_minutes=15) -> dict:
        ahash = args_hash(arguments)
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    """SELECT * FROM pending_approvals WHERE requester_id=? AND tool_name=? AND args_hash=?
                       ORDER BY created_at DESC LIMIT 1""",
                    (requester_id, tool_name, ahash),
                ).fetchone()
                result = None
                if row and not self._expired(row):
                    if row["status"] == "APPROVED":
                        conn.execute(
                            "UPDATE pending_approvals SET status='CONSUMED', consumed_at=? WHERE approval_id=?",
                            (_now().isoformat(), row["approval_id"]),
                        )
                        result = {"outcome": "execute", "approval": self._public(row)}
                    elif row["status"] == "PENDING":
                        result = {"outcome": "pending", "approval": self._public(row)}
                    elif row["status"] == "DENIED":
                        result = {"outcome": "denied", "approval": self._public(row)}

                if result is None:
                    approval_id = f"apr_{uuid.uuid4().hex[:10]}"
                    now = _now()
                    conn.execute(
                        """INSERT INTO pending_approvals
                           (approval_id, created_at, expires_at, requester_id, requester_name,
                            manager_id, manager_slack, tool_name, args_hash, arguments, reason, blast_radius, status)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'PENDING')""",
                        (approval_id, now.isoformat(), (now + timedelta(minutes=ttl_minutes)).isoformat(),
                         requester_id, requester_name, manager_id, manager_slack,
                         tool_name, ahash, json.dumps(arguments), reason, blast_radius),
                    )
                    new = conn.execute("SELECT * FROM pending_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                    result = {"outcome": "created", "approval": self._public(new)}
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            return result

    def decide(self, approval_id: str, approver_id: str, decision: str, ttl_minutes=15) -> dict:
        decision = (decision or "").upper()
        if decision not in ("APPROVED", "DENIED"):
            return {"error": "decision must be APPROVED or DENIED", "code": 400}
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT * FROM pending_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                err = None
                if not row:
                    err = {"error": "approval not found", "code": 404}
                elif row["requester_id"] == approver_id:
                    err = {"error": "requesters cannot decide their own request", "code": 403}
                elif row["manager_id"] != approver_id:
                    err = {"error": "only the routed manager may decide this request", "code": 403}
                elif row["status"] != "PENDING":
                    err = {"error": f"already {row['status']}", "code": 409}
                elif self._expired(row):
                    conn.execute("UPDATE pending_approvals SET status='EXPIRED' WHERE approval_id=?", (approval_id,))
                    err = {"error": "approval expired", "code": 410}
                if err:
                    conn.execute("COMMIT")
                    return err

                now = _now()
                conn.execute(
                    "UPDATE pending_approvals SET status=?, decided_by=?, decided_at=?, expires_at=? WHERE approval_id=?",
                    (decision, approver_id, now.isoformat(), (now + timedelta(minutes=ttl_minutes)).isoformat(), approval_id),
                )
                updated = conn.execute("SELECT * FROM pending_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            return self._public(updated)

    def get(self, approval_id: str):
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM pending_approvals WHERE approval_id=?", (approval_id,)).fetchone()
            return self._public(row) if row else None

    def pending_for(self, manager_id: str) -> list:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM pending_approvals WHERE manager_id=? AND status='PENDING' ORDER BY created_at", (manager_id,)
            ).fetchall()
            return [self._public(r) for r in rows if not self._expired(r)]
```[cite: 35]