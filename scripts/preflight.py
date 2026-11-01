#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Run (almost) the same checks as CI on your own machine, before you push.

    python scripts/preflight.py                  hygiene + compile + unit tests + version consistency
    python scripts/preflight.py --docker         also: docker compose up, run the demo, tear down
    python scripts/preflight.py --build          also: build sdist + wheel and run `twine check`
    python scripts/preflight.py --only version --tag v0.1.0
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".pytest_cache"}
SELF_EXEMPT = {"scripts/preflight.py", ".github/workflows/ci.yml"}   # they contain the patterns they look for
FORBIDDEN_TRACKED = re.compile(r"(^|/)(\.env|policy\.yaml|egress_secret)$|\.(db|db-wal|db-shm|pem|key)$")
SECRET_RX = re.compile(r"xox[bap]-[0-9A-Za-z-]{10,}|xapp-[0-9A-Za-z-]{10,}|BEGIN [A-Z ]*PRIVATE KEY")
CITE_RX = re.compile(r"\[" + "cite")
FENCE = "`" * 3


def tracked_files():
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        files = [f for f in out.split("\n") if f]
        if files:
            return files
    except Exception:
        pass
    files = []
    for d, dirs, names in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for n in names:
            files.append(os.path.relpath(os.path.join(d, n), ROOT).replace(os.sep, "/"))
    return files


def check_hygiene(**_):
    problems = []
    for rel in tracked_files():
        if rel in SELF_EXEMPT:
            continue
        if FORBIDDEN_TRACKED.search(rel):
            problems.append(f"{rel}: secret or state file must not be tracked")
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (UnicodeDecodeError, OSError):
            continue
        is_md = rel.lower().endswith(".md")
        for n, line in enumerate(text.splitlines(), 1):
            if not is_md and CITE_RX.search(line):
                problems.append(f"{rel}:{n}: stray pasted-citation marker")
            if not is_md and line.startswith(FENCE):
                problems.append(f"{rel}:{n}: stray markdown code fence")
            if SECRET_RX.search(line):
                problems.append(f"{rel}:{n}: possible secret")
    return problems


def check_compile(**_):
    r = subprocess.run([sys.executable, "-m", "compileall", "-q", "src", "tests", "examples", "scripts"], cwd=ROOT)
    return [] if r.returncode == 0 else ["some files do not compile"]


def check_tests(**_):
    env = {**os.environ, "PYTHONPATH": os.path.join(ROOT, "src") + os.pathsep + os.environ.get("PYTHONPATH", "")}
    r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-q"], cwd=ROOT, env=env)
    return [] if r.returncode == 0 else ["unit tests failed (output above)"]


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def check_version(tag=None, **_):
    problems = []
    m = re.search(r'^version\s*=\s*"([^"]+)"', _read("pyproject.toml"), re.M)
    if not m:
        return ["pyproject.toml has no version"]
    version = m.group(1)
    init = re.search(r'__version__\s*=\s*"([^"]+)"', _read("src/sovereignmcp/__init__.py"))
    if not init or init.group(1) != version:
        problems.append(f"src/sovereignmcp/__init__.py __version__ must equal pyproject version {version}")
    if not re.search(rf"^## \[?{re.escape(version)}\]?", _read("CHANGELOG.md"), re.M):
        problems.append(f"CHANGELOG.md has no '## {version}' entry")
    if tag and tag != f"v{version}":
        problems.append(f"tag {tag} does not match package version v{version}")
    return problems


def _healthy(url, seconds=90):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(2)
    return False


def check_docker(**_):
    if not shutil.which("docker"):
        return ["docker not found (install Docker Desktop, or leave out --docker)"]
    problems = []
    try:
        if subprocess.run(["docker", "compose", "up", "--build", "-d"], cwd=ROOT).returncode != 0:
            return ["docker compose up failed"]
        if not _healthy("http://127.0.0.1:8000/healthz"):
            subprocess.run(["docker", "compose", "logs", "--tail", "80"], cwd=ROOT)
            return ["gateway never became healthy"]
        if subprocess.run([sys.executable, "examples/demo_client.py", "--short"], cwd=ROOT).returncode != 0:
            subprocess.run(["docker", "compose", "logs", "--tail", "80"], cwd=ROOT)
            problems.append("the demo reported failing steps")
    finally:
        subprocess.run(["docker", "compose", "down", "-v"], cwd=ROOT)
    return problems


def check_build(**_):
    try:
        import build  # noqa: F401
    except ImportError:
        return ["missing tools: pip install build twine"]
    shutil.rmtree(os.path.join(ROOT, "dist"), ignore_errors=True)
    if subprocess.run([sys.executable, "-m", "build"], cwd=ROOT).returncode != 0:
        return ["python -m build failed"]
    files = [os.path.join("dist", f) for f in os.listdir(os.path.join(ROOT, "dist"))]
    r = subprocess.run([sys.executable, "-m", "twine", "check", *files], cwd=ROOT)
    return [] if r.returncode == 0 else ["twine check failed (pip install twine?)"]


CHECKS = {"hygiene": check_hygiene, "compile": check_compile, "tests": check_tests, "version": check_version,
          "docker": check_docker, "build": check_build}
DEFAULT = ["hygiene", "compile", "tests", "version"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--docker", action="store_true")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--only", help="comma-separated: " + ",".join(CHECKS))
    ap.add_argument("--tag", help="e.g. v0.1.0 (checked against the package version)")
    args = ap.parse_args()

    names = args.only.split(",") if args.only else DEFAULT + (["docker"] if args.docker else []) + (["build"] if args.build else [])
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        ap.error(f"unknown check(s): {unknown}")

    failed = {}
    for name in names:
        print(f"\n=== {name} ===", flush=True)
        problems = CHECKS[name](tag=args.tag)
        for p in problems:
            print(f"  FAIL: {p}")
        if problems:
            failed[name] = problems
        else:
            print("  ok")
    print("\n" + "=" * 40)
    for name in names:
        print(f"{'FAIL' if name in failed else 'PASS'}  {name}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
