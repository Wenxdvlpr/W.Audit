import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from email.message import Message
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from rivet.dynamic import validate_target, check_headers
from rivet.cli import main


class DynamicTests(unittest.TestCase):
    def test_target_allowlist(self):
        self.assertEqual("localhost", validate_target("http://localhost:8000/", ()))
        self.assertEqual("127.0.0.1", validate_target("http://127.0.0.1:8000/", ()))
        with self.assertRaises(ValueError):
            validate_target("https://example.com/", ())
        with patch("rivet.dynamic.socket.getaddrinfo", return_value=[(None, None, None, None, ("169.254.1.10", 443))]):
            with self.assertRaises(ValueError):
                validate_target("https://example.com/", ("example.com",))
        with patch("rivet.dynamic.socket.getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))]):
            self.assertEqual("example.com", validate_target("https://example.com/", ("example.com",)))
        for ip in ("169.254.169.254", "100.100.100.200", "168.63.129.16"):
            with self.assertRaises(ValueError):
                validate_target(f"http://{ip}/", (ip,))
        for url in ("file:///etc/passwd", "http://user:pass@localhost/", "http://localhost.evil.test/", "http://169.254.169.254/"):
            with self.assertRaises(ValueError):
                validate_target(url, ())

    def test_explicit_local_head_check(self):
        class Response:
            headers = Message()
            status = 200
        Response.headers["Content-Type"] = "text/plain"
        class Connection:
            def request(self, method, path, headers):
                self.method = method
                self.path = path
                self.headers = headers
            def getresponse(self):
                return Response()
            def close(self):
                pass
        connection = Connection()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dynamic"
            url = "http://127.0.0.1:8844/"
            stderr = io.StringIO()
            with patch("rivet.dynamic._PinnedHTTP", return_value=connection) as factory, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                self.assertEqual(2, main(["dynamic", url, "--out", str(out)]))
                self.assertEqual(0, main(["dynamic", url, "--test-environment", "--out", str(out)]))
            self.assertIn("EXPERIMENTAL", stderr.getvalue())
            self.assertIn("localhost", stderr.getvalue())
            report = json.loads((out / "security-report.json").read_text())
            self.assertEqual("dynamic", report["profile_name"])
            self.assertTrue(any(f["rule"] == "http/missing-nosniff" for f in report["findings"]))
            self.assertEqual("HEAD", connection.method)
            self.assertEqual(("127.0.0.1", 8844, "127.0.0.1"), factory.call_args.args)

    def test_allowed_hostname_uses_checked_ip_once(self):
        class Response:
            status = 200
            headers = Message()
        class Connection:
            def request(self, method, path, headers):
                self.method = method
            def getresponse(self):
                return Response()
            def close(self):
                pass
        connection = Connection()
        with patch("rivet.dynamic.socket.getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 80))]) as dns, patch("rivet.dynamic._PinnedHTTP", return_value=connection) as factory:
            _, checks = check_headers("http://test.example/", ("test.example",))
        self.assertEqual(1, dns.call_count)
        self.assertEqual(("test.example", 80, "8.8.8.8"), factory.call_args.args)
        self.assertEqual("HEAD", connection.method)
        self.assertEqual("CHECKED", checks[0].status)

    def test_ipv4_mapped_metadata_is_blocked(self):
        with self.assertRaises(ValueError):
            validate_target("http://[::ffff:169.254.169.254]/", ("::ffff:169.254.169.254",))

    def test_real_loopback_head_request(self):
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                calls.append(self.path)
                self.send_response(200)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
            def log_message(self, *args):
                pass
        try:
            server = HTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError:
            self.skipTest("loopback bind denied by sandbox")
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            findings, checks = check_headers(f"http://127.0.0.1:{server.server_port}/status", ())
            self.assertEqual([], findings)
            self.assertEqual("CHECKED", checks[0].status)
            self.assertEqual(["/status"], calls)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
