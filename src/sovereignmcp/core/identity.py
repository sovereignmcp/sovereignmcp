# SPDX-License-Identifier: PolyForm-Shield-1.0.0
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
        except Exception as exc:  # keep last good policy on a bad edit
            if initial:
                raise
            print(f"[policy] reload failed, keeping previous policy: {exc}", flush=True)

    # ---- settings -------------------------------------------------------
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

    # ---- Slack approval bridge ------------------------------------------
    def authenticate_bridge(self, headers) -> None:
        """The Slack bot has its OWN credential. It may only call decide-via-slack."""
        self._load()
        expected = ((self._policy.get("approval_bridge") or {}).get("token_sha256") or "").lower()
        auth = headers.get("authorization", "")
        if not expected or not auth.lower().startswith("bearer "):
            raise AuthError(401, "Missing bridge credential")
        if not hmac.compare_digest(sha256_hex(auth[7:].strip()), expected):
            raise AuthError(403, "Invalid bridge credential")

    def user_ids(self) -> list:
        self._load()
        return list(self._by_id)

    def slack_id_of(self, user_id):
        self._load()
        return (self._by_id.get(user_id) or {}).get("slack_user_id")

    def user_by_slack_id(self, slack_user_id):
        self._load()
        if not isinstance(slack_user_id, str) or not slack_user_id:
            return None
        return self._by_slack.get(slack_user_id)

    # ---- authentication -------------------------------------------------
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
