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
