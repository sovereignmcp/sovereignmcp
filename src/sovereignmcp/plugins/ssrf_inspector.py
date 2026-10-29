# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""SSRF inspection for `fetch_url`-style tools. Fails closed.

Resolves the hostname ITSELF and checks every address, so tricks like decimal/hex/octal
IPs, IPv4-mapped IPv6, userinfo (http://evil@169.254.169.254) and names that resolve to
internal addresses (169.254.169.254.nip.io) are all caught.

Limits you must document: (1) DNS rebinding, since the fetcher resolves again after this check;
(2) redirects, since the fetcher must re-validate every hop or disable redirects. The real fix
for both is an egress firewall / a fetcher that connects to the IP we validated.
"""
import fnmatch
import ipaddress
import re
import socket
from urllib.parse import urlsplit

DEFAULT_SCHEMES = ("http", "https")
BLOCKED_PORTS = frozenset({22, 23, 25, 110, 135, 139, 143, 445, 1433, 1521, 2375, 2376, 3306, 3389,
                           5432, 5900, 6379, 9200, 10250, 11211, 27017})
METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.goog", "metadata", "instance-data",
                            "instance-data.ec2.internal", "metadata.azure.internal"})
METADATA_IPS = frozenset(ipaddress.ip_address(x) for x in
                         ("169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "192.0.0.192"))
INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".corp", ".private", ".home.arpa")
EXTRA_BLOCKED_NETS = [ipaddress.ip_network(n) for n in ("64:ff9b::/96", "2002::/16", "2001::/32", "100.64.0.0/10")]


def _v(action, reason, blast="Low"):
    return {"action": action, "reason": reason, "blast_radius": blast}


def _parse_legacy_ipv4(host: str):
    """Classic inet_aton forms: 127.1, 0x7f.1, 2130706433, 0177.0.0.1. Platform-independent."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts):
        return None
    nums = []
    for p in parts:
        try:
            if p.lower().startswith("0x"):
                nums.append(int(p, 16))
            elif len(p) > 1 and p.startswith("0"):
                nums.append(int(p, 8))
            else:
                nums.append(int(p, 10))
        except ValueError:
            return None
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n << (8 * (3 - i))
    return value


def _literal_ip(host: str):
    if ":" in host:
        return ipaddress.ip_address(host)  # ValueError if malformed
    legacy = _parse_legacy_ipv4(host)
    return ipaddress.IPv4Address(legacy) if legacy is not None else None


def _check_ip(ip):
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip in METADATA_IPS:
        return "cloud metadata endpoint"
    if any(n.version == ip.version and ip in n for n in EXTRA_BLOCKED_NETS):
        return "tunnel, translation or carrier-grade NAT address"
    if not ip.is_global:
        return "internal, loopback, link-local or reserved address"
    return None


def _default_resolver(host, port):
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return sorted({i[4][0] for i in infos})


def inspect_url(url, rules=None, resolver=None) -> dict:
    rules = rules or {}
    resolver = resolver or _default_resolver
    if not isinstance(url, str) or not url.strip():
        return _v("deny", "Fail-closed: missing or non-string URL", "Unknown")
    url = url.strip()
    if len(url) > 2048:
        return _v("deny", "Fail-closed: URL too long", "Unknown")
    if not url.isascii():
        return _v("deny", "Non-ASCII URL (use punycode)", "Possible homograph")
    if re.search(r"[\s\\\x00-\x1f\x7f]", url):
        return _v("deny", "URL contains whitespace, control characters or a backslash", "Parser-confusion attempt")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return _v("deny", "Malformed URL", "Malformed URL")

    scheme = parts.scheme.lower()
    if scheme not in tuple(s.lower() for s in rules.get("allowed_schemes", DEFAULT_SCHEMES)):
        return _v("deny", f"Scheme '{scheme}' is not allowed", f"scheme: {scheme}")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return _v("deny", "Credentials in URL are not allowed (userinfo trick)", "Userinfo in URL")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        return _v("deny", "URL has no host", "No host")
    if "%" in host:
        return _v("deny", "Zone identifiers are not allowed", "Zone id")
    port = port or (443 if scheme == "https" else 80)

    if host in METADATA_HOSTS:
        return _v("deny", "Cloud metadata hostname", f"{host}")
    try:
        literal = _literal_ip(host)
    except ValueError:
        return _v("deny", "Malformed IP literal", "Malformed IP")
    if literal is not None:
        ips = [literal]
    else:
        if host == "localhost" or host.endswith(INTERNAL_SUFFIXES):
            return _v("deny", f"Internal hostname '{host}'", host)
        try:
            ips = [ipaddress.ip_address(a.split("%")[0]) for a in resolver(host, port)]
        except Exception:
            return _v("deny", f"Fail-closed: could not resolve '{host}'", host)
        if not ips:
            return _v("deny", f"Fail-closed: '{host}' resolved to nothing", host)

    shown = ", ".join(str(i) for i in ips)
    for ip in ips:
        why = _check_ip(ip)
        if why:
            return _v("deny", f"Blocked: {host} -> {ip} ({why})", f"{scheme}://{host}:{port} -> {shown}")

    blast = f"{scheme}://{host}:{port} -> {shown}"
    if port in set(rules.get("blocked_ports", BLOCKED_PORTS)):
        return _v("approve", f"Sensitive service port {port} needs review", blast)
    allowed_hosts = rules.get("allowed_hosts")
    if allowed_hosts:
        if not any(fnmatch.fnmatchcase(host, p.lower()) for p in allowed_hosts):
            return _v("approve", f"'{host}' is not on the allowed-host list", blast)
    elif rules.get("unknown_hosts", "allow") == "approve":
        return _v("approve", f"'{host}' needs review (unknown_hosts: approve)", blast)
    return _v("allow", "Public host", blast)
