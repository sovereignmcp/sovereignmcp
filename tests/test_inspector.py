import unittest

from plugins.inspector import PayloadInspector

RULES = {
    "run_sql": {"sql_inspect": True, "sql_arg": "query"},
    "update_user": {"forbidden_arg_values": {"role": ["admin", "superadmin", "root"]}},
    "delete_database": {"requires_approval": True},
}


def inspect(tool, args):
    return PayloadInspector.inspect(tool, args, RULES)["action"]


class InspectorTests(unittest.TestCase):
    def test_reads_allowed(self):
        self.assertEqual(inspect("run_sql", {"query": "SELECT * FROM orders WHERE id = 1"}), "allow")
        self.assertEqual(inspect("run_sql", {"query": "SELECT count(*) FROM orders"}), "allow")

    def test_writes_need_approval(self):
        self.assertEqual(inspect("run_sql", {"query": "DROP TABLE users"}), "approve")
        self.assertEqual(inspect("run_sql", {"query": "UPDATE users SET role='admin'"}), "approve")
        self.assertEqual(inspect("run_sql", {"query": "DELETE FROM orders"}), "approve")

    def test_stacked_denied(self):
        self.assertEqual(inspect("run_sql", {"query": "SELECT 1; DROP TABLE users"}), "deny")
        self.assertEqual(inspect("run_sql", {"query": "SELECT 1; SELECT pg_sleep(1)"}), "deny")

    def test_fail_closed(self):
        self.assertEqual(inspect("run_sql", {}), "deny")
        self.assertEqual(inspect("run_sql", {"query": ""}), "deny")
        self.assertEqual(inspect("run_sql", {"query": "SELECT * FROM ("}), "deny")

    def test_side_effect_functions_need_approval(self):
        self.assertEqual(inspect("run_sql", {"query": "SELECT pg_sleep(10);"}), "approve")
        # evasions: whatever the parser does, it must never be allowed
        for q in ("SELECT pg_sleep/**/(10)", "SELECT pg_catalog.pg_sleep(10)", 'SELECT "pg_sleep"(10)',
                  "SELECT PG_SLEEP (10)", "SELECT lo_import('/etc/passwd')", "SELECT 1 INTO OUTFILE '/tmp/x'"):
            self.assertNotEqual(inspect("run_sql", {"query": q}), "allow", q)

    def test_escalation(self):
        self.assertEqual(inspect("update_user", {"target_user": "x", "role": "SuperAdmin"}), "deny")
        self.assertEqual(inspect("update_user", {"target_user": "x", "patch": {"role": "root"}}), "deny")
        self.assertEqual(inspect("update_user", {"target_user": "x", "metadata": {"Role": "sUpErAdMiN"}}), "deny")
        self.assertEqual(inspect("update_user", {"target_user": "x", "role": "viewer"}), "allow")

    def test_escalation_evasions(self):
        self.assertEqual(inspect("update_user", {"role": ["superadmin"]}), "deny")                 # list value
        self.assertEqual(inspect("update_user", {"role": ["viewer", "ADMIN"]}), "deny")            # list, mixed
        self.assertEqual(inspect("update_user", {"role": {"name": "admin"}}), "deny")              # dict value
        self.assertEqual(inspect("update_user", {"patch": '{"Role": "admin"}'}), "deny")           # JSON in a string
        self.assertEqual(inspect("update_user", {" role ": "admin"}), "deny")                      # padded key
        self.assertEqual(inspect("update_user", {"role": " Admin "}), "deny")                      # padded value
        self.assertEqual(inspect("update_user", {"\uff52\uff4f\uff4c\uff45": "admin"}), "deny")    # full-width key
        deep = {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": 1}}}}}}}}}}
        self.assertEqual(inspect("update_user", deep), "deny")                                     # too deep -> fail closed

    def test_tool_level_approval(self):
        self.assertEqual(inspect("delete_database", {}), "approve")


if __name__ == "__main__":
    unittest.main()