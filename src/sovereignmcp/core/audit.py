# SPDX-License-Identifier: PolyForm-Shield-1.0.0
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
