# Threat model (v0.1, written to be challenged)

This describes what SovereignMCP defends, what it assumes, and what it does **not** do.
Status words are literal: **Tested** = an automated test in this repo exercises it. **Designed** = built but not yet covered by an
end-to-end test. **Gap** = not implemented. Nothing here has had an independent security review yet.

## What we protect
- Protected systems behind MCP servers (databases, shells, URLs, email, ...) from actions a person was not allowed to take.
- The record of who asked for what, and who approved it.
- Payload data (arguments, results), which must not leave the customer's machine in hybrid mode.

## Who we defend against
| Actor | Capability |
|---|---|
| **A1 Limited user** | Has a valid token for a low-privilege role and tries to do more than the role allows |
| **A2 Misled agent** | The model is prompt-injected or simply wrong and calls tools the person never intended |
| **A3 Hostile MCP server or tool description** | Returns poisoned tool metadata or output |
| **A4 Network attacker** | Can observe or modify traffic between components |
| **A5 Host attacker** | Can read or write files on the gateway machine |
| **A6 Compromised control plane** (hybrid mode) | Can send forged decisions or read what the gateway sends it |

## Assumptions (not enforced by this software)
1. **The gateway is the only route to protected servers.** Enforce this with network rules and with `SOVEREIGN_UPSTREAM_AUTH`, so the server refuses anyone who skips the gateway.
2. **TLS terminates in front of the gateway.** Tokens travel as bearer tokens; do not run it over plain HTTP outside localhost.
3. Tokens are long random secrets held by the right people; the policy file's permissions are restricted.
4. The audit key (`SOVEREIGN_AUDIT_KEY`) is secret and held apart from the audit database.

## Controls
| Threat | Control | Status |
|---|---|---|
| A1 uses a tool outside their role | Intersection Rule (person AND agent), enforced on every call and in `tools/list` | Tested |
| A1 picks a more powerful agent | Per-agent credentials (`X-Agent-Key`), optional `require_agent_credentials` | Tested (identity); off by default |
| A1/A2 uses an unlisted protocol method (`resources/read`, `prompts/get`) | Default-deny method allowlist | Tested |
| A1 smuggles an escalation in arguments (`role: superadmin`, nested, cased, listed, JSON-in-string) | Argument inspection | Tested |
| A1/A2 destructive or exfiltrating SQL | Parsed read-only allowlist, stacked/unparseable SQL denied, side-effect function denylist, length cap | Tested (needs sqlglot in CI) |
| A1/A2 dangerous shell command | Hard-deny patterns, allowlist, metacharacters need approval | Tested; **risk reduction only, not a sandbox** |
| A1/A2 SSRF to metadata or internal hosts | Resolves DNS itself, checks every address, blocks disguised IPs and userinfo tricks | Tested; DNS rebinding and redirects are **Gap** (fetcher's job) |
| Parser differential (duplicate keys) | Strict JSON: duplicates and NaN/Infinity rejected | Tested |
| Session riding | Session id bound to the person who initialized it | Tested |
| Self-approval, wrong approver, replay, altered arguments, expiry | Approval engine binds to person + tool + exact arguments, single use, expiring, routed manager only | Tested |
| A5 edits the audit log | Hash chain (HMAC-keyed with `SOVEREIGN_AUDIT_KEY`) | Tested; **tamper-evident, not immutable**; deleting the newest rows needs an external copy of the head hash |
| Secrets leaking into audit rows and Slack messages | Key-based and value-based redaction | Tested; best effort |
| Credential stuffing | Per-source block after repeated failures, capped logging | Tested |
| Oversized or malformed requests | Body size limit, SQL length cap, depth-safe JSON | Tested |
| A6 forged decision | Ed25519 signature on a pinned key, nonce, args fingerprint, expiry, **local approval engine has the final say** | Tested |
| A6 reads payloads | Closed-schema egress with keyed hashes; canary test | Tested |
| Audit write fails | The call is not forwarded (log before forward) | Designed |
| Policy file edited badly | Last good policy is kept | Designed |
| Cloud outage | Gateway keeps enforcing with local policy; approvals stay pending | Designed |

## Known gaps (do not rely on us for these yet)
- **A3 tool poisoning and rug pulls:** tool descriptions are not pinned or scanned, and tool **results** are not inspected.
- **Prompt-injection awareness:** no tracking of untrusted content before sensitive calls.
- **Streaming (SSE) responses** are not filtered; JSON-RPC batches are rejected.
- **No token expiry, rotation, or SSO.** Tokens are static hashes.
- **The approvals table keeps raw arguments** until pruned (they are needed to run an approved call). Protect the database file; a retention job is not built.
- **Agent credentials are optional** by default.
- **Session bindings are in memory**; a restart makes clients re-initialize.
- **Rate limiting** covers failed logins per source address only.
- **A host attacker (A5)** who can read the policy file and database can learn a lot; we only make tampering detectable.
- **No independent review or penetration test yet.**

## Out of scope
Securing the MCP server's own code, the model itself, endpoint compromise of a person's laptop, and anything outside the gateway's network path.

## Reporting
See `SECURITY.md`. Bypass reports are the most valuable thing you can send us; each fixed bypass gets a regression test.
