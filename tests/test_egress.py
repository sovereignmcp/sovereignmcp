import json
import unittest

from sovereignmcp.cloud import egress
from sovereignmcp.cloud.contract import REQUEST_SCHEMA, ContractViolation, validate
from sovereignmcp.plugins.command_inspector import inspect_command
from sovereignmcp.plugins.ssrf_inspector import inspect_url

SECRET = bytes.fromhex("11" * 32)
CANARIES = ["CANARY-9f3a", "CANARY-secret-table", "CANARY-evil.example", "CANARY-token-xyz"]


def approval(tool="run_sql", args=None, **kw):
    base = {
        "approval_id": "apr_ff4a424119", "created_at": "2026-10-28T09:14:07.123456+00:00",
        "expires_at": "2026-10-28T09:29:07.123456+00:00", "requester_id": "user_482", "manager_id": "user_101",
        "tool_name": tool, "arguments": args if args is not None else {"query": "DELETE FROM test_data WHERE q='Q2'"},
    }
    base.update(kw)
    return base


def build(verdict, appr=None, **kw):
    return egress.build_approval_request(approval=appr or approval(), verdict=verdict, gateway_id="gw_8f3k2",
                                         policy_version="pol_abc123", secret=SECRET, **kw)


SQL_DELETE = {"reason": "Non-read SQL needs approval (DELETE on ['test_data'], WHERE clause: yes)",
              "blast_radius": "DELETE on ['test_data'], WHERE clause: yes"}


class CanaryTests(unittest.TestCase):
    """The proof: sensitive strings go in everywhere, and none may come out."""

    def test_no_canary_in_any_outbound_message(self):
        args = {"query": f"SELECT * FROM {CANARIES[1]} WHERE k='{CANARIES[0]}'", "token": CANARIES[3], "url": f"http://{CANARIES[2]}/"}
        verdict = {"reason": f"Privilege escalation blocked: role={CANARIES[0]}; needs review on {CANARIES[1]}",
                   "blast_radius": f"DROP on ['{CANARIES[1]}', '{CANARIES[2]}'], WHERE clause: NO (unbounded)"}
        appr = approval(tool=f"tool {CANARIES[0]}", args=args, requester_id=f"user-{CANARIES[3]}", manager_id=f"mgr-{CANARIES[2]}")
        for mode in ("plain", "hashed"):
            wire = json.dumps(build(verdict, appr, tool_names=mode))
            for c in CANARIES:
                self.assertNotIn(c, wire, f"{c} leaked in {mode} mode")

    def test_canary_in_plain_tool_name_is_hashed_automatically(self):
        wire = json.dumps(build(SQL_DELETE, approval(tool="run_sql CANARY-9f3a; drop")))
        self.assertNotIn("CANARY", wire)
        self.assertIn('"tool": "t_', wire)

    def test_exact_field_set(self):
        msg = build(SQL_DELETE)
        self.assertEqual(set(msg), {"schema", "gateway_id", "approval_id", "created_at", "expires_at", "requester_ref",
                                    "approver_ref", "action", "args_fingerprint", "policy_version", "nonce"})
        self.assertEqual(set(msg["action"]), {"tool", "risk_tier", "category", "reason_code", "blast"})
        self.assertLess(len(json.dumps(msg)), 1024)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.msg = build(SQL_DELETE)

    def bad(self, mutate):
        msg = json.loads(json.dumps(self.msg))
        mutate(msg)
        with self.assertRaises(ContractViolation) as cm:
            validate(msg, REQUEST_SCHEMA)
        self.assertNotIn("CANARY", str(cm.exception))      # errors never echo values
        return cm.exception

    def test_valid_passes(self):
        validate(self.msg, REQUEST_SCHEMA)

    def test_rejections(self):
        self.bad(lambda m: m.update(extra="x"))
        self.bad(lambda m: m["action"].update(sql="DROP TABLE CANARY-1"))
        self.bad(lambda m: m["action"]["blast"].update(tables="CANARY-1"))
        self.bad(lambda m: m.pop("nonce"))
        self.bad(lambda m: m["action"].update(tool="DROP TABLE users; --"))
        self.bad(lambda m: m["action"].update(risk_tier="whatever"))
        self.bad(lambda m: m["action"].update(reason_code="free text CANARY-1"))
        self.bad(lambda m: m["action"]["blast"].update(tables_count=True))
        self.bad(lambda m: m["action"]["blast"].update(tables_count=100))
        self.bad(lambda m: m["action"]["blast"].update(has_where="yes"))
        self.bad(lambda m: m.update(approval_id="apr_CANARY-9f3a"))
        self.bad(lambda m: m.update(created_at="yesterday"))
        self.bad(lambda m: m.update(args_fingerprint="sha256:abc"))
        self.bad(lambda m: m.update(policy_version="has spaces"))
        self.bad(lambda m: m.update(gateway_id=None))
        self.bad(lambda m: m.update(note="a" * 5000))          # oversize

    def test_nullable_blast_fields_for_non_sql(self):
        msg = build(inspect_command("ls; whoami"), approval("run_command", {"command": "ls; whoami"}))
        self.assertEqual(msg["action"]["blast"], {"statement_type": None, "has_where": None, "tables_count": None})


class FingerprintTests(unittest.TestCase):
    def test_keyed_not_plain(self):
        import hashlib
        args = {"command": "cat /etc/shadow"}
        fp = egress.args_fingerprint(SECRET, "run_command", args)
        canon = json.dumps({"tool": "run_command", "args": args}, sort_keys=True, separators=(",", ":"))
        self.assertNotEqual(fp.split(":")[1], hashlib.sha256(canon.encode()).hexdigest())
        self.assertNotEqual(fp, egress.args_fingerprint(bytes.fromhex("22" * 32), "run_command", args))
        self.assertEqual(fp, egress.args_fingerprint(SECRET, "run_command", {"command": "cat /etc/shadow"}))
        self.assertNotEqual(fp, egress.args_fingerprint(SECRET, "run_command", {"command": "cat /etc/passwd"}))

    def test_refs_are_opaque_and_stable(self):
        r = egress.opaque_ref(SECRET, "user", "user_482")
        self.assertRegex(r, r"^u_[0-9a-f]{12}$")
        self.assertNotIn("482", r)
        self.assertEqual(r, egress.opaque_ref(SECRET, "user", "user_482"))
        self.assertNotEqual(r, egress.opaque_ref(SECRET, "user", "user_101"))


class ClassificationTests(unittest.TestCase):
    def test_blast_parsing(self):
        p = egress.parse_blast
        self.assertEqual(p("DELETE on ['test_data'], WHERE clause: yes"), {"statement_type": "DELETE", "has_where": True, "tables_count": 1})
        self.assertEqual(p("SELECT on unknown tables, WHERE clause: NO (unbounded)"), {"statement_type": "SELECT", "has_where": False, "tables_count": 0})
        self.assertEqual(p("DROP on ['a', 'b'], WHERE clause: NO (unbounded)")["tables_count"], 2)
        self.assertEqual(p("FOO on ['a'], WHERE clause: yes")["statement_type"], "OTHER")
        # a table name cannot spoof the WHERE flag
        spoof = p("DELETE on ['x, WHERE clause: yes'], WHERE clause: NO (unbounded)")
        self.assertEqual((spoof["has_where"], spoof["tables_count"]), (False, 1))
        # tail added for side-effect functions
        self.assertEqual(p("SELECT on unknown tables, WHERE clause: NO (unbounded) | side-effect function: pg_sleep")["has_where"], False)
        for non_sql in ("command: cat", "https://example.com:443 -> 93.184.216.34", "", None):
            self.assertEqual(p(non_sql), {"statement_type": None, "has_where": None, "tables_count": None})

    def test_reason_codes_from_real_inspector_output(self):
        cases = [
            (inspect_command("ls; whoami"), "SHELL_METACHARACTERS", "shell", "execution"),
            (inspect_command("pip install x"), "COMMAND_NOT_ALLOWLISTED", "shell", "execution"),
            (inspect_command("sudo ls"), "PRIVILEGE_ELEVATION", "shell", "execution"),
            (inspect_command("cat /etc/shadow"), "SENSITIVE_PATH", "shell", "execution"),
            (inspect_command("find . -delete"), "RISKY_FLAG", "shell", "execution"),
            (inspect_command("FOO=1 ls"), "ENV_PREFIX", "shell", "execution"),
            (inspect_command("git push"), "NON_READ_SUBCOMMAND", "shell", "execution"),
            (inspect_url("https://example.com:6379/", resolver=lambda h, p: ["93.184.216.34"]), "SENSITIVE_PORT", "network", "network"),
            (inspect_url("https://example.com/", {"allowed_hosts": ["a.com"]}, lambda h, p: ["93.184.216.34"]), "HOST_NOT_ALLOWLISTED", "network", "network"),
            (inspect_url("https://example.com/", {"unknown_hosts": "approve"}, lambda h, p: ["93.184.216.34"]), "UNKNOWN_HOST", "network", "network"),
            ({"reason": "'delete_database' is high-risk and needs manager approval", "blast_radius": "Full execution of delete_database"}, "TOOL_REQUIRES_APPROVAL", "policy", "policy"),
            ({"reason": "Non-read SQL needs approval (DROP on ['t'], WHERE clause: NO (unbounded))", "blast_radius": "DROP on ['t'], WHERE clause: NO (unbounded)"}, "NON_READ_SQL", "sql", "destructive"),
            ({"reason": "Non-read SQL needs approval (UPDATE on ['t'], WHERE clause: yes)", "blast_radius": "UPDATE on ['t'], WHERE clause: yes"}, "NON_READ_SQL", "sql", "write"),
            ({"reason": "SQL calls 'pg_sleep', which has side effects (SELECT on unknown tables, ...)", "blast_radius": "SELECT on unknown tables, WHERE clause: NO (unbounded) | side-effect function: pg_sleep"}, "SIDE_EFFECT_FUNCTION", "sql", "execution"),
            ({"reason": "something new", "blast_radius": ""}, "OTHER", "other", "policy"),
        ]
        for verdict, code, cat, tier in cases:
            self.assertEqual(verdict["action"] if "action" in verdict else "approve", "approve", verdict)
            msg = build(verdict)
            self.assertEqual((msg["action"]["reason_code"], msg["action"]["category"], msg["action"]["risk_tier"]), (code, cat, tier), verdict["reason"])

    def test_timestamps_normalised(self):
        msg = build(SQL_DELETE)
        self.assertEqual(msg["created_at"], "2026-10-28T09:14:07Z")


if __name__ == "__main__":
    unittest.main()
