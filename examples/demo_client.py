# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""End-to-end demo against a running gateway:  python examples/demo_client.py [base_url]   (needs: pip install httpx)"""
import re
import sys

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
INTERN, MANAGER, CTO = "demo-intern-token", "demo-manager-token", "demo-cto-token"
HDR = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
failures = []


def rpc(token, method, params=None, rid=1):
    r = httpx.post(f"{BASE}/mcp", headers={**HDR, "Authorization": f"Bearer {token}"},
                   json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}, timeout=30)
    return r.json()


def call(token, tool, args):
    return rpc(token, "tools/call", {"name": tool, "arguments": args})


def step(title, out, ok):
    print(f"\n--- {'PASS' if ok else 'FAIL'}: {title}\n{out}")
    if not ok:
        failures.append(title)


def blocked(out):
    return "error" in out and out["error"]["code"] in (-32001, -32002)


def text_of(out):
    return out.get("result", {}).get("content", [{}])[0].get("text", "")


names = [t["name"] for t in rpc(INTERN, "tools/list")["result"]["tools"]]
step("1. Intern's tool list hides delete_database", names, "delete_database" not in names and "read_metrics" in names)
out = call(INTERN, "read_metrics", {})
step("2. Intern reads metrics (allowed)", out, "Q3 Revenue" in text_of(out))
step("3. Intern tries delete_database (blocked)", out := call(INTERN, "delete_database", {}), blocked(out))
step("4. Intern tries role=superadmin (blocked)", out := call(INTERN, "update_user", {"target_user": "rohan", "role": "superadmin"}), blocked(out))
out = call(INTERN, "run_sql", {"query": "SELECT * FROM orders LIMIT 5"})
step("5. Intern runs SELECT (allowed)", out, "EXECUTED" in text_of(out))
step("6. Intern stacks SQL (blocked)", out := call(INTERN, "run_sql", {"query": "SELECT 1; DROP TABLE users"}), blocked(out))
step("7. Intern runs `rm -rf /` (blocked outright)", out := call(INTERN, "run_command", {"command": "rm -rf /"}), blocked(out))
step("8. Intern fetches the cloud metadata IP (blocked)", out := call(INTERN, "fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"}), blocked(out))

q2 = {"query": "DELETE FROM test_data WHERE quarter = 'Q2'"}
out = call(INTERN, "run_sql", q2)
step("9. Intern deletes Q2 test data (held for approval)", out, "NOT EXECUTED" in text_of(out))
apr_id = re.search(r"apr_[0-9a-f]+", text_of(out)).group(0)


def decide(token):
    return httpx.post(f"{BASE}/approvals/{apr_id}/decide", json={"decision": "APPROVED"},
                      headers={**HDR, "Authorization": f"Bearer {token}"})


r = decide(INTERN)
step("10. Intern tries to approve own request (refused)", (r.status_code, r.json()), r.status_code == 403)
r = decide(CTO)
step("11. Wrong person (not the routed manager) tries to approve (refused)", (r.status_code, r.json()), r.status_code == 403)
r = decide(MANAGER)
step("12. Routed manager approves", (r.status_code, r.json()), r.status_code == 200)
out = call(INTERN, "run_sql", q2)
step("13. Intern repeats the same call (executes once)", out, "EXECUTED" in text_of(out))
out = call(INTERN, "run_sql", q2)
step("14. Repeat again (needs a fresh approval)", out, "NOT EXECUTED" in text_of(out))

r = httpx.get(f"{BASE}/audit/verify", headers={"Authorization": f"Bearer {MANAGER}"})
step("15. Audit chain verifies", r.json(), r.json().get("valid") is True)

print("\n" + ("ALL STEPS PASSED" if not failures else f"{len(failures)} STEP(S) FAILED: {failures}"))
sys.exit(1 if failures else 0)
