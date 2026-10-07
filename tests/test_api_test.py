import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import threading
import tempfile
import unittest
from unittest.mock import patch

from rivet.api_test import MAX_REQUESTS, MAX_RESPONSE_BYTES, run_safe_api_tests
from rivet.cli import main


class SafeApiTests(unittest.TestCase):
    def test_live_localhost_probe_uses_real_http_server(self):
        hits = []
        redirected_hits = []
        redirect_location = ""

        class RedirectTargetHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                redirected_hits.append((self.command, self.path))
                self.send_response(200)
                self.end_headers()
            def log_message(self, *_):
                pass

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, status):
                self.send_response(status)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Access-Control-Allow-Origin", "https://rivet.invalid")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(b"ok")
            def do_GET(self):
                hits.append((self.command, self.path, self.headers.get("Authorization")))
                if self.path == "/protected":
                    self._reply(200 if self.headers.get("Authorization") == "Bearer valid-test-token" else 401)
                elif self.path.startswith("/items/"):
                    self._reply(400 if self.path.endswith("/not-a-valid-uuid") else 200)
                elif self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", redirect_location)
                    self.end_headers()
                else:
                    self._reply(200)
            def do_HEAD(self):
                hits.append((self.command, self.path, self.headers.get("Authorization")))
                self._reply(200)
            def do_OPTIONS(self):
                hits.append((self.command, self.path, self.headers.get("Authorization")))
                self._reply(204)
            def log_message(self, *_):
                pass

        redirected_server = None
        try:
            redirected_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectTargetHandler)
            redirect_location = f"http://127.0.0.1:{redirected_server.server_port}/redirected"
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except OSError as exc:
            if redirected_server is not None:
                redirected_server.server_close()
            self.skipTest(f"loopback bind unavailable: {exc}")
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        redirected_worker = threading.Thread(target=redirected_server.serve_forever, daemon=True)
        worker.start()
        redirected_worker.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            def status(path, token=None):
                import http.client
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                headers = {"Authorization": f"Bearer {token}"} if token else {}
                connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                result = response.status
                response.read()
                connection.close()
                return result

            self.assertEqual((401, 200), (status("/protected"), status("/protected", "valid-test-token")))
            spec = {
                "openapi": "3.1.0",
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                "paths": {
                    "/public": {"get": {}},
                    "/protected": {"get": {"security": [{"bearer": []}]}},
                    "/items/{item_id}": {"get": {"parameters": [{"name": "item_id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}]}},
                    "/redirect": {"get": {}},
                },
            }
            with tempfile.TemporaryDirectory() as temp:
                schema = Path(temp) / "openapi.json"
                schema.write_text(json.dumps(spec))
                findings, checks, _, _ = run_safe_api_tests(base, schema, ())
                rules = {finding.rule for finding in findings}
                self.assertEqual("CHECKED", checks[0].status)
                self.assertNotIn("api/auth-missing", rules)
                self.assertNotIn("api/auth-invalid", rules)
                self.assertTrue(any(path == "/protected" and token == "Bearer invalid-rivet-test-token" for _, path, token in hits))
                self.assertTrue(any(path == "/items/not-a-valid-uuid" for _, path, _ in hits))
                self.assertTrue(any(method == "OPTIONS" and path == "/public" for method, path, _ in hits))
                redirect_get_count = sum(method == "GET" and path == "/redirect" for method, path, _ in hits)
                self.assertEqual(1, redirect_get_count, "the redirect response should be requested once")
                self.assertEqual([], redirected_hits, "the cross-origin Location target must not be requested")
                self.assertIn("1 cross-origin; none followed", checks[0].detail)
                for target in ("https://example.com", "http://169.254.169.254"):
                    with self.assertRaises(ValueError):
                        run_safe_api_tests(target, schema, ())
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
            redirected_server.shutdown()
            redirected_server.server_close()
            redirected_worker.join(timeout=2)

    def test_read_only_openapi_probes_and_report(self):
        hits = []
        read_sizes = []

        class Response:
            def __init__(self, status, headers=None):
                self.status = status
                self.headers = headers or {}
            def read(self, size):
                read_sizes.append(size)
                return b"x" * min(size, 1)

        class Connection:
            def __init__(self, host, port, address):
                self.request_data = None
            def request(self, method, path, body=None, headers=None):
                self.request_data = (method, path, body, headers or {})
                hits.append(self.request_data)
            def getresponse(self):
                method, path, body, headers = self.request_data
                if method == "OPTIONS":
                    return Response(204, {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
                if path.startswith("/users/") and headers.get("Authorization"):
                    return Response(401)
                if path == "/preview" and headers.get("Content-Type") == "text/plain":
                    return Response(415)
                if path == "/preview" and body == b"{":
                    return Response(400)
                if path == "/redirect":
                    return Response(302, {"Location": "https://external.invalid/"})
                return Response(200)
            def close(self):
                pass

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            schema = Path(__file__).parent / "fixtures/api-openapi/openapi.json"
            base = "http://localhost/"
            with patch("rivet.api_test._PinnedHTTP", Connection):
                findings, checks, routes, matrix = run_safe_api_tests(base, schema, ())
                rules = {finding.rule for finding in findings}
                self.assertIn("api/auth-missing", rules)
                self.assertNotIn("api/auth-invalid", rules)
                self.assertIn("api/uuid-validation", rules)
                self.assertNotIn("api/content-type", rules)
                self.assertNotIn("api/malformed-json", rules)
                self.assertIn("api/cors-wildcard-credentials", rules)
                self.assertIn("api/header-nosniff", rules)
                self.assertEqual("CHECKED", checks[0].status)
                self.assertIn("observed 1 redirect Location value(s), 1 cross-origin; none followed", checks[0].detail)
                self.assertEqual({"INFERRED", "UNKNOWN"}, {cell["status"] for cell in matrix})
                self.assertTrue(all(route["evidence_status"] == "INFERRED" for route in routes))
                self.assertTrue(any(headers.get("Content-Type") == "text/plain" for _, _, _, headers in hits))
                self.assertTrue(any(body == b"{" for _, _, body, _ in hits))
                self.assertTrue(any(headers.get("Authorization") == "Bearer invalid-rivet-test-token" for _, _, _, headers in hits))
                self.assertEqual({MAX_RESPONSE_BYTES + 1}, set(read_sizes))
                warning = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(warning):
                    self.assertEqual(0, main(["api-test", base, "--openapi", str(schema), "--test-environment", "--out", str(root / "reports")]))
                self.assertIn("EXPERIMENTAL", warning.getvalue())
                self.assertIn("localhost", warning.getvalue())
                self.assertTrue((root / "reports/security-report.json").is_file())
                self.assertFalse(any("external.invalid" in path for _, path, *_ in hits))

    def test_api_request_limit_stops_at_configured_cap(self):
        calls = []
        class Response:
            status = 204
            headers = {}
            def read(self, size):
                return b""
        class Connection:
            def __init__(self, host, port, address):
                pass
            def request(self, method, path, body=None, headers=None):
                calls.append((method, path))
            def getresponse(self):
                return Response()
            def close(self):
                pass
        with tempfile.TemporaryDirectory() as temp:
            schema = Path(temp) / "openapi.json"
            schema.write_text(json.dumps({"paths": {f"/read/{i}": {"get": {}} for i in range(60)}}))
            with patch("rivet.api_test._PinnedHTTP", Connection):
                _, checks, routes, _ = run_safe_api_tests("http://localhost", schema, ())
        self.assertEqual(MAX_REQUESTS, len(calls))
        self.assertEqual(MAX_REQUESTS, len(set(calls)))
        self.assertEqual("PARTIAL", checks[0].status)
        self.assertEqual(60, len(routes))

    def test_api_probes_require_explicit_test_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            schema = Path(temp) / "openapi.json"
            schema.write_text('{"paths":{}}')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(2, main(["api-test", "http://localhost/", "--openapi", str(schema)]))


if __name__ == "__main__":
    unittest.main()
