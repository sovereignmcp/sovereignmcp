"""Deep parameter inspection. Fails closed.

Returns {"action": "allow" | "approve" | "deny", "reason": str, "blast_radius": str}
"""
import json
import re
import unicodedata

import sqlglot
from sqlglot import exp

# SECURED: Fixed internal imports to use the public namespace
from sovereignmcp.plugins.command_inspector import inspect_command
from sovereignmcp.plugins.ssrf_inspector import inspect_url

def _nodes(*names):
    return tuple(getattr(exp, n) for n in names if hasattr(exp, n))

READ_ROOTS = _nodes("Select", "Union", "Except", "Intersect", "SetOperation", "Subquery")
WRITE_NODES = _nodes(
    "Insert", "Update", "Delete", "Drop", "Alter", "AlterTable", "Create", "Command", "Merge",
    "TruncateTable", "Into", "Copy", "Grant", "Revoke", "Set", "Use", "Transaction", "Commit",
    "Rollback", "Pragma", "Attach", "Detach",
)

DEFAULT_BLOCKED_FUNCTIONS = (
    "pg_sleep", "pg_sleep_for", "pg_sleep_until", "sleep", "benchmark",
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "pg_file_write", "load_file",
    "lo_import", "lo_export", "lo_get", "dblink", "dblink_exec", "dblink_connect",
    "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile", "set_config",
    "nextval", "setval", "xp_cmdshell", "sp_executesql",
)

MAX_DEPTH = 8

class _TooDeep(Exception):
    pass

def _norm(value) -> str:
    """Normalize so 'ROLE', ' role ', and full-width 'ｒｏｌｅ' all compare equal."""
    return unicodedata.normalize("NFKC", str(value)).casefold().strip()

def _walk(obj, depth=0):
    """Yield (key, value) for every dict entry at any depth, including inside JSON-in-a-string."""
    if depth > MAX_DEPTH:
        raise _TooDeep()
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from _walk(v, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk(item, depth + 1)
    elif isinstance(obj, str):
        s = obj.strip()
        if s and s[0] in "{[":
            try:
                parsed = json.loads(s)
            except ValueError:
                return
            yield from _walk(parsed, depth + 1)

def _leaves(value, depth=0):
    """Every scalar inside a value (a value may itself be a list or dict)."""
    if depth > MAX_DEPTH:
        raise _TooDeep()
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaves(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            yield from _leaves(v, depth + 1)
    else:
        yield value

def _verdict(action, reason, blast="Low"):
    return {"action": action, "reason": reason, "blast_radius": blast}

def _dangerous_call(sql: str, blocked) -> str | None:
    """Spot side-effect function calls even through comments, quoting or schema qualification."""
    text = unicodedata.normalize("NFKC", sql)
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"--[^\n]*", " ", text).lower()
    for name in blocked:
        if re.search(rf"(?<![a-z0-9_]){re.escape(name)}[\"`\]]?\s*\(", text):
            return name
    if re.search(r"\binto\s+(outfile|dumpfile)\b", text):
        return "into outfile/dumpfile"
    return None

def _ast_function_names(stmt) -> set:
    names = set()
    try:
        for node in stmt.find_all(exp.Func):
            n = node.name if isinstance(node, exp.Anonymous) else node.sql_name()
            names.add(str(n).lower())
    except Exception:
        pass
    return names

class PayloadInspector:
    @classmethod
    def inspect(cls, tool_name: str, arguments: dict, tool_rules: dict, sql_dialect=None) -> dict:
        rules = (tool_rules or {}).get(tool_name, {})

        forbidden = {_norm(k): {_norm(x) for x in v} for k, v in rules.get("forbidden_arg_values", {}).items()}
        if forbidden:
            try:
                for key, value in _walk(arguments):
                    bad = forbidden.get(_norm(key))
                    if bad is None:
                        continue
                    for leaf in _leaves(value):
                        if _norm(leaf) in bad:
                            return _verdict("deny", f"Privilege escalation blocked: {key}={leaf}", "IAM escalation")
            except _TooDeep:
                return _verdict("deny", "Fail-closed: arguments nested too deeply", "Unknown")

        if rules.get("sql_inspect"):
            blocked = {f.lower() for f in DEFAULT_BLOCKED_FUNCTIONS} | {f.lower() for f in rules.get("sql_blocked_functions", [])}
            verdict = cls._inspect_sql(arguments.get(rules.get("sql_arg", "query")), sql_dialect, blocked)
            if verdict["action"] != "allow":
                return verdict

        if rules.get("command_inspect"):
            verdict = inspect_command(arguments.get(rules.get("command_arg", "command")), rules)
            if verdict["action"] != "allow":
                return verdict

        if rules.get("url_inspect"):
            verdict = inspect_url(arguments.get(rules.get("url_arg", "url")), rules)
            if verdict["action"] != "allow":
                return verdict

        if rules.get("requires_approval"):
            return _verdict("approve", f"'{tool_name}' is high-risk and needs manager approval", f"Full execution of {tool_name}")

        return _verdict("allow", "Passed inspection")

    @classmethod
    def _inspect_sql(cls, sql, dialect, blocked=()):
        if not isinstance(sql, str) or not sql.strip():
            return _verdict("deny", "Fail-closed: missing or non-string SQL", "Unknown")
        try:
            statements = [s for s in sqlglot.parse(sql, read=dialect) if s is not None]
        except Exception as exc:
            return _verdict("deny", f"Fail-closed: unparseable SQL ({type(exc).__name__})", "Malformed SQL")
        if not statements:
            return _verdict("deny", "Fail-closed: empty SQL", "None")
        if len(statements) > 1:
            return _verdict("deny", "Stacked SQL statements are not allowed", f"{len(statements)} statements")

        stmt = statements[0]
        risky_fn = _dangerous_call(sql, blocked) or next((n for n in _ast_function_names(stmt) if n in blocked), None)
        is_read_root = isinstance(stmt, READ_ROOTS)
        has_write = stmt.find(*WRITE_NODES) is not None if WRITE_NODES else True

        if is_read_root and not has_write and not risky_fn:
            return _verdict("allow", "Read-only SQL")

        tables = sorted({t.name for t in stmt.find_all(exp.Table) if t.name})
        has_where = stmt.find(exp.Where) is not None
        blast = f"{stmt.key.upper()} on {tables or 'unknown tables'}, WHERE clause: {'yes' if has_where else 'NO (unbounded)'}"
        if risky_fn:
            blast += f" | side-effect function: {risky_fn}"
            return _verdict("approve", f"SQL calls '{risky_fn}', which has side effects ({blast})", blast)
        return _verdict("approve", f"Non-read SQL needs approval ({blast})", blast)
```[cite: 35]