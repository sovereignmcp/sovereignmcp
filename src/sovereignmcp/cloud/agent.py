"""Outbound-only cloud client. The gateway always dials out (HTTPS 443); the cloud never dials in.

Pass in the gateway's existing httpx.AsyncClient (proxy settings from HTTPS_PROXY are honored).
"""
import asyncio
import random
from urllib.parse import urlsplit

# SECURED: Fixed internal imports to use the public namespace
from sovereignmcp.cloud.contract import ACK_SCHEMA, SCHEMA_ACK, ContractViolation, validate
from sovereignmcp.cloud.egress import build_approval_request


class CloudAgent:
    def __init__(self, client, *, base_url: str, gateway_id: str, gateway_key: str, secret: bytes,
                 pinned_keys: dict, tool_names: str = "plain", policy_version: str = "pol_unknown",
                 allow_insecure_localhost: bool = False, log=print):
        parts = urlsplit(base_url)
        local = parts.hostname in ("localhost", "127.0.0.1", "::1")
        if parts.scheme != "https" and not (allow_insecure_localhost and local and parts.scheme == "http"):
            raise ValueError("cloud URL must be https")
        if not pinned_keys:
            raise ValueError("pinned cloud public keys are required (decisions can't be verified without them)")
        if tool_names not in ("plain", "hashed"):
            raise ValueError("tool_names must be 'plain' or 'hashed'")
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.gateway_id = gateway_id
        self.gateway_key = gateway_key
        self.secret = secret
        self.keys = pinned_keys
        self.tool_names = tool_names
        self.policy_version = policy_version
        self.log = log

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.gateway_key}", "X-Gateway-Id": self.gateway_id}

    async def submit_approval(self, approval: dict, verdict: dict) -> bool:
        """Best-effort. Failing here never blocks the local approval flow."""
        try:
            message = build_approval_request(approval=approval, verdict=verdict, gateway_id=self.gateway_id,
                                             policy_version=self.policy_version, secret=self.secret,
                                             tool_names=self.tool_names)
        except (ContractViolation, KeyError, ValueError) as exc:
            self.log(f"[cloud] refused to send approval request: {type(exc).__name__}")   # never log the message
            return False
        try:
            r = await self.client.post(f"{self.base_url}/v1/gateway/approvals", json=message,
                                       headers=self._headers(), timeout=10)
        except Exception as exc:
            self.log(f"[cloud] approval submit failed: {type(exc).__name__}")
            return False
        ok = r.status_code in (200, 201, 202, 409)      # 409 = already registered
        if not ok:
            self.log(f"[cloud] approval submit failed: HTTP {r.status_code}")
        return ok

    async def fetch_decisions(self, wait: int = 25) -> list:
        r = await self.client.get(f"{self.base_url}/v1/gateway/decisions", params={"wait": wait},
                                  headers=self._headers(), timeout=wait + 10)
        if r.status_code == 204:
            return []
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        items = r.json().get("decisions", [])
        return items[:50] if isinstance(items, list) else []

    async def ack(self, result: dict) -> None:
        if not result.get("approval_id"):
            return
        message = {"schema": SCHEMA_ACK, "approval_id": result["approval_id"],
                   "outcome": result["outcome"], "code": result["code"][:40]}
        try:
            validate(message, ACK_SCHEMA)
            await self.client.post(f"{self.base_url}/v1/gateway/decisions/ack", json=message,
                                   headers=self._headers(), timeout=10)
        except Exception as exc:
            self.log(f"[cloud] ack failed: {type(exc).__name__}")

    async def run(self, process, stop: asyncio.Event = None, wait: int = 25) -> None:
        """process(decision_message) -> result dict (see cloud.verify.process_decision). Runs until stopped."""
        backoff = 1.0
        while not (stop and stop.is_set()):
            try:
                decisions = await self.fetch_decisions(wait)
                backoff = 1.0
                for message in decisions:
                    result = await asyncio.to_thread(process, message)
                    self.log(f"[cloud] decision {result.get('approval_id')}: {result['outcome']} ({result['code']})")
                    await self.ack(result)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.log(f"[cloud] poll failed: {type(exc).__name__}; retrying")
                await asyncio.sleep(backoff + random.random())
                backoff = min(backoff * 2, 60.0)
```[cite: 44]