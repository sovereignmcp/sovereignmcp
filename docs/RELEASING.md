# Releasing SovereignMCP (PyPI + GHCR + GitHub Release)

Everything after the one-time setup is: **tag, push, wait.**

## 0. Decide the name first (names are hard to change after publishing)
- Open https://pypi.org/project/sovereignmcp/ : a **404 means the name is free**.
- A similarly named package, `sovereign-mcp-gateway`, already exists on PyPI (a gateway for MCP servers). Decide whether that overlap is acceptable for your brand *before* you publish and market; renaming later is expensive.

## 1. One-time setup (about 10 minutes)
**PyPI (Trusted Publishing, no API token stored anywhere)**
1. Create a PyPI account and turn on 2FA.
2. PyPI, then *Your account*, then *Publishing*, then **Add a new pending publisher**:
   - Project name: `sovereignmcp`
   - Owner: `sovereignmcp`  Repository: `sovereignmcp`
   - Workflow name: `release.yml`  Environment: `pypi`
3. GitHub repo, then *Settings*, then *Environments*, then **New environment** named `pypi`. Add yourself as a required reviewer so a release needs your click.

**GHCR (Docker image)** needs no setup. After the first release: GitHub profile, *Packages*, `sovereignmcp`, *Package settings*, set visibility to **Public**.

## 2. Every release
```bash
python scripts/preflight.py --docker --build     # every line must say PASS
# bump the version in pyproject.toml AND src/sovereignmcp/__init__.py, add a CHANGELOG.md entry
git add -A && git commit -m "Release 0.1.0" && git push
# wait for CI on main to be green, then:
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```
Watch *Actions*, *Release*. Approve the `pypi` environment when asked. The workflow then publishes to PyPI, pushes
`ghcr.io/sovereignmcp/sovereignmcp:0.1.0` and `:latest`, and creates a GitHub Release from the CHANGELOG (marked pre-release while you are in alpha).

## 3. Check it like a stranger would
```bash
pipx install sovereignmcp && sovereignmcp --help
docker run --rm ghcr.io/sovereignmcp/sovereignmcp:0.1.0 sovereignmcp --help
```
Then change the README install line to `pipx install sovereignmcp`, and add a `docker run` example.

## If something fails
- Read the failing job's log in *Actions*. Fix, then bump to `0.1.1`: **PyPI never lets you re-upload the same version.**
- A tag whose version doesn't match `pyproject.toml` is rejected on purpose by the first job.
