# SovereignMCP

**A zero-trust gateway for AI agent tool calls.** It sits between an AI assistant and your internal
[MCP](https://modelcontextprotocol.io) servers, so an agent can only do what the *specific person* using it is allowed to do,
risky calls wait for a human, and every decision lands in a tamper-evident audit log on your own machine.

> **Status: alpha.** Tested with Cursor and a mock MCP server. Not independently audited. Read [Limits](#limits) before relying on it.

## The problem

A company connects an AI assistant to its systems with one shared service account. An intern asks it to "clear out the old test data."
The assistant has no idea the intern may not delete records, so it does. The logs only say `AI_Service_Account`.

With SovereignMCP in front, the intern's assistant never even *sees* `delete_records`, a destructive `DELETE` is held for the intern's
manager, and the log says exactly who asked for what.

## What it does

- **Per-person identity.** Every request carries the human's token; policy is per person and role.
- **Intersection Rule.** A tool runs only if the person's role *and* the agent are both allowed. Enforced on every call, not just by hiding tools.
- **Deep inspection.** Looks inside arguments, not just tool names:
  - privilege escalation values (`role: superadmin`, at any depth, any casing, lists, JSON-in-strings)
  - SQL parsed with a real parser: reads pass, writes need approval, stacked or unparseable SQL is blocked, side-effect functions (`pg_sleep`, `lo_import`...) need approval
  - shell commands: catastrophic commands and reverse shells are denied outright, anything unfamiliar needs approval
  - URLs (SSRF): cloud-metadata IPs, private ranges, disguised IPs (`2130706433`, `0x7f000001`), userinfo tricks
- **Human approval.** Risky calls return "NOT EXECUTED, pending" immediately. Only the routed manager can approve (never the requester). The requester then repeats the identical call and it runs once. Approvals expire and are bound to the exact arguments.
- **Tamper-evident audit.** Hash-chained SQLite log, optionally HMAC-keyed, secrets redacted, written *before* a call is forwarded.
- **Shadow mode.** Log what *would* be blocked without blocking anything. A safe way to start.

## Quickstart (60 seconds, demo)

```bash
git clone https://github.com/sovereignmcp/sovereignmcp && cd sovereignmcp
docker compose up --build            # gateway on :8000 + a deliberately trusting fake MCP server

# second terminal
pip install httpx
python examples/demo_client.py       # plays the intern story; every step should say PASS
```

The demo uses public **demo tokens**. The gateway refuses to start with them outside demo mode.

## Use it for real

```bash
pip install "git+https://github.com/sovereignmcp/sovereignmcp.git"

sovereignmcp init                    # writes policy.yaml (shadow mode ON), prints your admin token once
export SOVEREIGN_AUDIT_KEY=...       # printed by init; protects the audit log from re-forging
export SOVEREIGN_UPSTREAM=https://your-mcp-server.internal/mcp
sovereignmcp serve --port 8000
```

Then edit `policy.yaml`: add people (`sovereignmcp hash-token` hashes a token), give each a `manager:`, list their `allowed_tools`, and
add `tool_rules`. Watch the audit log in shadow mode, then set `shadow_mode: false` to enforce. See `examples/policy.example.yaml`.

Check the audit chain any time: `sovereignmcp verify-audit`.

## Connect an MCP client (Cursor)

Point the client at the gateway with the person's token (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "company-tools": {
      "url": "http://localhost:8000/mcp",
      "headers": { "Authorization": "Bearer <the person's token>", "X-Agent-ID": "default_agent" }
    }
  }
}
```

If your client can't send custom headers, use the stdio bridge: `pip install "sovereignmcp[bridges]"` and run
`python -m sovereignmcp.bridges.cursor_bridge` with `SOVEREIGN_TOKEN` set in the client's `env` block.

## Slack approvals (optional)

The gateway DMs the routed manager an Approve / Deny message. In your Slack app enable **Socket Mode** (no public URL needed), bot scopes
`chat:write` and `im:write`, then:

1. In `policy.yaml` give each approver a `slack_user_id`, and add `approval_bridge: { token_sha256: <hash of a random secret> }`.
2. Run the gateway with `SLACK_BOT_TOKEN` set.
3. Run the bot: `SLACK_BOT_TOKEN=... SLACK_APP_TOKEN=... SOVEREIGN_BRIDGE_TOKEN=<the secret> python -m sovereignmcp.bridges.slack_bot`

The bot never holds a manager's token. It reports *who clicked* (Slack's own user ID); the gateway maps that to a person and enforces
"only the routed manager". Never put Slack tokens in code or commit them.

## Hybrid mode (optional, outbound-only)

A hosted control plane can broker approvals while your data stays home. The gateway dials **out** over HTTPS; nothing connects in. What leaves is a
strict, closed-schema metadata message (tool, risk tier, reason code, coarse SQL shape, a *keyed* hash of the arguments), never the arguments,
results, tokens or URLs. Decisions come back **Ed25519-signed** and are checked against a pinned public key, matched to a local approval and
re-checked by the local approval engine before anything runs. The wire contract is in [`src/sovereignmcp/cloud/contract.py`](src/sovereignmcp/cloud/contract.py),
and `tests/test_egress.py` is a canary test that fails if payload data ever appears in an outbound message. Try it with `examples/mock_cloud.py`.

## Limits

Please read these. A security tool should be honest about what it does not do.

- **Shell inspection reduces risk; it does not make a shell safe.** Run commands in a sandbox with least privilege.
- **SQL:** side effects inside a plain `SELECT` are caught by a function denylist, not by proof. Use read-only database credentials as well.
- **SSRF:** the gateway validates the URL before the fetch, but the fetcher resolves DNS again (DNS rebinding) and may follow redirects. Use an egress firewall or a fetcher that pins the validated IP.
- **Agent identity** (`X-Agent-ID`) is client-supplied; bind it to a credential before trusting it.
- **Audit log:** tamper-*evident*, not immutable. Export the head hash off the machine; deleting the newest rows is only detectable against an external copy.
- **Streaming:** only JSON responses are filtered; streamed `tools/list` replies are refused in enforce mode. JSON-RPC batches are rejected.
- **Tokens** are static hashes: no expiry or SSO yet.

## License

SovereignMCP is **source-available** under the [PolyForm Shield License 1.0.0](LICENSE) (not an OSI "open source" license).
You may use it freely, including commercially and inside your company, and modify it. You may **not** provide a product that competes with it,
including hosted or managed versions. There is no automatic conversion to another license. See [COMMERCIAL.md](COMMERCIAL.md).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).
