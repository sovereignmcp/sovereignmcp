# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Shell command inspection for `run_command`-style tools.

Principle: unknown => human. Catastrophic and reverse-shell patterns are denied outright
(no approval possible). Anything that is not a plain, allowlisted, metacharacter-free
command goes to a manager for approval.

This reduces risk; it does NOT make a shell safe. Run commands in a sandbox/container
with least privilege, and treat this as the second line of defense.
"""
import re
import shlex
import unicodedata

MAX_LEN = 4096

DEFAULT_ALLOWED = frozenset({
    "ls", "pwd", "cat", "head", "tail", "wc", "grep", "echo", "date", "whoami", "id", "uname",
    "df", "du", "ps", "uptime", "which", "file", "stat", "sort", "tree", "find",
})
SUBCOMMANDS = {"git": frozenset({"status", "log", "diff", "show", "branch", "rev-parse"})}
FIND_RISKY = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}
# command -> letter that makes it write/modify something when used as a short flag
RISKY_SHORT = {"sort": "o", "tree": "o", "date": "s"}
RISKY_LONG = {"sort": ("--output",), "date": ("--set",)}

_META = re.compile(r"[;&|<>`$\n\r]")
_SENSITIVE_PATH = re.compile(
    r"(^|/)(\.ssh|\.aws|\.gnupg|\.kube|\.netrc|\.pgpass|id_rsa|id_ed25519|shadow|sudoers|credentials)(/|$)"
    r"|(^|/)\.env(\.|$)|/proc/[^/]+/environ|\.docker/config\.json|\.git-credentials",
    re.I,
)
_SEG = re.compile(r"\s*(?:;|&&|\|\||\||&|\n)\s*")

_DANGEROUS_TARGETS = {
    "/", "/*", "~", "~/*", "$home", "$home/*", "${home}", "${home}/*", "/home", "/home/*",
    "/etc", "/etc/*", "/usr", "/usr/*", "/var", "/var/*", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/root", "/opt", "/srv", "/dev", "/sys", "/proc",
}

_HARD_DENY = [
    ("filesystem formatting", r"\bmkfs(\.\w+)?\b"),
    ("raw disk write", r"\bdd\b[^;&|]*\bof=/dev/"),
    ("raw disk write", r">\s*/dev/(sd|hd|vd|nvme|xvd|mmcblk)\w*"),
    ("fork bomb", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    ("recursive chmod/chown on /", r"\b(chmod|chown)\b[^;&|]*\s-[a-z]*r[a-z]*\b[^;&|]*\s/(\s|$)"),
    ("system shutdown", r"(?:^|[;&|]\s*|\bsudo\s+)(shutdown|reboot|poweroff|halt|init\s+[06])\b"),
    ("kill all processes", r"\bkill\s+(-[a-z0-9]+\s+)+-1(\s|$)|\bkillall5\b"),
    ("recursive delete from /", r"\bfind\s+(/|~)(\s|$)[^;&|]*(-delete|-exec\s+(\S*/)?rm\b)"),
    ("reverse shell (/dev/tcp)", r"/dev/(tcp|udp)/"),
    ("reverse shell (netcat exec)", r"\b(nc|ncat|netcat)\b[^;&|]*\s-[a-z]*[ec]\b"),
    ("interactive reverse shell", r"\b(ba|z|da|k)?sh\s+-i\b"),
    ("reverse shell (socat)", r"\bsocat\b[^;&|]*\b(exec|system):"),
    ("reverse shell (scripting language)", r"\b(python\d*|perl|ruby|php|node|lua)\b\s+-[a-z]*[cer]\b[^;&|]*\b(socket|fsockopen|pty\.spawn|dup2)\b"),
    ("reverse shell (fifo)", r"\bmkfifo\b[^;&]*\b(nc|ncat|telnet)\b"),
    ("download piped to shell", r"\b(curl|wget|fetch)\b[^;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"),
    ("download piped to interpreter", r"\b(curl|wget|fetch)\b[^;&]*\|\s*(sudo\s+)?(python\d*|perl|ruby|node|php)\b"),
    ("decode and execute", r"\bbase64\s+(-d|--decode)\b[^;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"),
    ("execute downloaded script", r"\$\(\s*(curl|wget)\b"),
    ("windows disk format", r"\bformat\s+[a-z]:"),
    ("windows recursive delete", r"\b(del|erase)\b[^;&|]*\s/[sq]\b[^;&|]*\s[a-z]:(\s|$)"),
    ("windows recursive delete", r"\b(rd|rmdir)\b[^;&|]*\s/s\b[^;&|]*\s[a-z]:(\s|$)"),
    ("powershell encoded/download-exec", r"\b(powershell|pwsh)\b[^;&]*(downloadstring|invoke-expression|\biex\b|\s-enc(odedcommand)?\b)"),
]
_HARD_DENY = [(name, re.compile(rx)) for name, rx in _HARD_DENY]


def _v(action, reason, blast="Low"):
    return {"action": action, "reason": reason, "blast_radius": blast}


def _flat(cmd: str) -> str:
    """Strip quoting/escaping tricks so r''m -rf / and r\\m -rf / look like rm -rf /."""
    s = unicodedata.normalize("NFKC", cmd).lower()
    s = re.sub(r"\$\{?ifs\}?", " ", s)
    s = re.sub(r"\$[@*]", "", s)
    s = s.replace("'", "").replace('"', "").replace("\\", "")
    return re.sub(r"\s+", " ", s)


def _rm_catastrophe(flat: str):
    for seg in _SEG.split(flat):
        toks = seg.split()
        if "rm" not in toks:
            continue
        args = toks[toks.index("rm") + 1:]
        if "--no-preserve-root" in args:
            return "rm --no-preserve-root"
        recursive = any(
            (a.startswith("-") and not a.startswith("--") and "r" in a) or a == "--recursive" for a in args
        )
        if recursive:
            for a in args:
                if a.startswith("-"):
                    continue
                norm = re.sub(r"/+", "/", a).rstrip("/") or "/"
                if norm in _DANGEROUS_TARGETS:
                    return "recursive delete of a system or home directory"
    return None


def _hard_deny(flat: str):
    hit = _rm_catastrophe(flat)
    if hit:
        return hit
    for name, rx in _HARD_DENY:
        if rx.search(flat):
            return name
    return None


def _risky_flag(base: str, tokens: list):
    args = tokens[1:]
    if base == "find":
        return next((t for t in args if t in FIND_RISKY), None)
    letter = RISKY_SHORT.get(base)
    for t in args:
        if letter and re.fullmatch(rf"-[a-zA-Z]*{letter}[a-zA-Z]*.*", t) and not t.startswith("--"):
            return t
        if any(t == f or t.startswith(f + "=") for f in RISKY_LONG.get(base, ())):
            return t
    return None


def inspect_command(command, rules=None) -> dict:
    rules = rules or {}
    if isinstance(command, (list, tuple)) and command and all(isinstance(c, str) for c in command):
        command = shlex.join(command)
    if not isinstance(command, str) or not command.strip():
        return _v("deny", "Fail-closed: missing or non-string command", "Unknown")
    if len(command) > MAX_LEN or "\x00" in command:
        return _v("deny", "Fail-closed: command too long or contains NUL", "Unknown")

    hit = _hard_deny(_flat(command))
    if hit:
        return _v("deny", f"Blocked outright: {hit}", hit)

    try:
        tokens = shlex.split(command)
    except ValueError:
        return _v("deny", "Fail-closed: unparseable command (unbalanced quotes)", "Malformed command")
    if not tokens:
        return _v("deny", "Fail-closed: empty command", "None")

    prog = tokens[0]
    blast = f"command: {prog}"
    if _META.search(command):
        return _v("approve", "Shell metacharacters (; | & < > ` $ newline) need a human to review", blast)
    if "=" in prog:
        return _v("approve", "Environment-variable prefix needs review", blast)

    base = prog.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base in ("sudo", "su", "doas", "runas"):
        return _v("approve", "Privilege elevation needs review", blast)

    allowed = DEFAULT_ALLOWED | frozenset(SUBCOMMANDS) | {c.lower() for c in rules.get("allowed_commands", [])}
    if base not in allowed:
        return _v("approve", f"'{base}' is not on the allowed-command list", blast)
    subs = SUBCOMMANDS.get(base)
    if subs and (len(tokens) < 2 or tokens[1] not in subs):
        sub = tokens[1] if len(tokens) > 1 else "(none)"
        return _v("approve", f"'{base} {sub}' is not a read-only subcommand", blast)
    flag = _risky_flag(base, tokens)
    if flag:
        return _v("approve", f"Flag '{flag}' can write or execute", blast)
    if any(_SENSITIVE_PATH.search(t) for t in tokens[1:]):
        return _v("approve", "Touches a sensitive path (keys, credentials, .env, shadow)", blast)
    return _v("allow", "Plain allowlisted command")
