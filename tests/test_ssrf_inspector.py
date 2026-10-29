import unittest

from sovereignmcp.plugins.ssrf_inspector import inspect_url

PUBLIC = lambda host, port: ["93.184.216.34"]
STUBS = {
    "169.254.169.254.nip.io": ["169.254.169.254"],
    "rebind.example": ["93.184.216.34", "10.0.0.5"],   # one bad address poisons the whole answer
    "intranet-alias.example": ["192.168.1.10"],
    "v6.example": ["2606:2800:220:1:248:1893:25c8:1946"],
}


def resolver(host, port):
    if host in STUBS:
        return STUBS[host]
    if host == "nxdomain.example":
        raise OSError("no such host")
    return ["93.184.216.34"]


def act(url, rules=None):
    return inspect_url(url, rules, resolver)["action"]


class SSRFTests(unittest.TestCase):
    def test_internal_and_metadata_denied(self):
        for u in [
            "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8000/", "http://localhost/",
            "http://localhost./", "http://foo.localhost/", "http://[::1]/", "http://2130706433/",
            "http://0x7f000001/", "http://017700000001/", "http://127.1/", "http://0/", "http://10.0.0.5/",
            "http://192.168.1.1/", "http://172.16.0.1/", "http://100.64.0.1/", "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:a9fe:a9fe]/", "http://metadata.google.internal/", "http://[fd00:ec2::254]/",
            "http://169.254.169.254.nip.io/", "http://rebind.example/", "http://intranet-alias.example/",
            "http://printer.lan/", "http://100.100.100.200/",
        ]:
            self.assertEqual(act(u), "deny", u)

    def test_parser_tricks_denied(self):
        for u in [
            "http://evil.com@169.254.169.254/", "http://evil.com\\@169.254.169.254/",
            "http://user:pw@example.com/", "file:///etc/passwd", "gopher://127.0.0.1:6379/_x",
            "ftp://example.com/", "http://\u24db\u24de\u24d2\u24d0\u24db\u24d7\u24de\u24e2\u24e3/",
            "http://example.com:99999/", "http:///nohost", "http://exa mple.com/", "http://[::1/",
        ]:
            self.assertEqual(act(u), "deny", u)

    def test_fail_closed(self):
        for u in ["", None, 5, "http://nxdomain.example/", "x" * 3000]:
            self.assertEqual(act(u), "deny", repr(u)[:30])

    def test_public_allowed(self):
        for u in ["https://example.com/page?q=1", "http://example.com:8080/x", "https://v6.example/"]:
            self.assertEqual(act(u), "allow", u)

    def test_sensitive_port_needs_approval(self):
        self.assertEqual(act("https://example.com:6379/"), "approve")
        self.assertEqual(act("http://example.com:22/"), "approve")

    def test_host_policy(self):
        rules = {"allowed_hosts": ["*.github.com", "api.example.com"]}
        self.assertEqual(act("https://api.github.com/x", rules), "allow")
        self.assertEqual(act("https://example.com/x", rules), "approve")
        self.assertEqual(act("https://example.com/x", {"unknown_hosts": "approve"}), "approve")
        # allowlist never overrides the internal-address block
        self.assertEqual(act("http://127.0.0.1/", {"allowed_hosts": ["127.0.0.1"]}), "deny")


if __name__ == "__main__":
    unittest.main()
