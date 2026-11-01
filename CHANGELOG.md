# Changelog

## Unreleased

Security hardening from a self-audit of the gateway.

- **Fixed: unguarded protocol methods.** Methods other than `tools/*` (for example `resources/read`) used to pass straight through. They are now denied by default; opt in with `allowed_methods`.
- **Fixed: session riding.** MCP session ids are bound to the person who initialized them; unknown or foreign ids get 404.
- **Fixed: parser differentials.** Request bodies with duplicate keys or non-standard JSON constants are rejected.
- **Added: agent credentials** (`token_sha256` per agent, `X-Agent-Key`, `require_agent_credentials`) so agent identity is not self-declared.
- **Added: upstream credential** (`SOVEREIGN_UPSTREAM_AUTH`) so the MCP server can refuse callers that bypass the gateway.
- **Added: failed-login protection** (per-source block with `Retry-After`, capped audit logging), request size limit, SQL length cap.
- **Improved: secret redaction** now scrubs secret-looking VALUES (tokens, keys, JWTs, URL credentials, card numbers) in audit rows and Slack messages, not only values under a "password" key.
- Added `docs/THREAT_MODEL.md`.

## 0.1.0 - 2026-10-30

First public alpha.

**Gateway**
- Per-person identity from a bearer token; the Intersection Rule (person's role AND agent must both allow a tool), enforced on every call and in `tools/list`.
- Deep inspection: privilege-escalation values, SQL (parsed, read-only allowlist, side-effect function denylist), shell commands, SSRF-safe URLs.
- Human approvals: held calls are routed to the person's manager, bound to the exact arguments, single use, expiring; requesters can never approve their own request.
- Tamper-evident, hash-chained audit log (optionally HMAC-keyed), written before a call is forwarded.
- Shadow mode (log only), `sovereignmcp init | serve | hash-token | verify-audit`.
- Slack approvals (Socket Mode bot plus interactive DM) and a stdio bridge for MCP clients such as Cursor.
- Hybrid mode, outbound-only: closed-schema metadata egress with a canary test, Ed25519-signed decisions verified against a pinned key.

**Known limits** (see the README): shell inspection reduces risk but is not a sandbox; DNS rebinding and redirects are the fetcher's job; agent identity is client-supplied; audit log is tamper-evident, not immutable; no SSO or token expiry yet; streaming responses are not filtered.
