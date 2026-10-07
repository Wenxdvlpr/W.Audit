"""Bounded, read-only API probes driven by a local OpenAPI JSON document."""

from __future__ import annotations

import json
import http.client
from pathlib import Path
import re
import ssl
from urllib.parse import urlencode, urljoin, urlsplit

from .dynamic import _PinnedHTTP, _PinnedHTTPS, _target
from .model import Check, Finding

MAX_SCHEMA_BYTES = 2_000_000
MAX_OPERATIONS = 100
MAX_REQUESTS = 100
MAX_RESPONSE_BYTES = 1_000_000
SAFE_METHODS = {"GET", "HEAD"}
METHODS = SAFE_METHODS | {"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def _sample(parameter: dict) -> str:
    schema = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else {}
    if schema.get("format") == "uuid":
        return "00000000-0000-4000-8000-000000000001"
    if schema.get("type") == "integer":
        return "1"
    if schema.get("type") == "boolean":
        return "true"
    return "rivet-test"


def _invalid_auth(doc: dict, security: list) -> dict[str, str]:
    schemes = doc.get("components", {}).get("securitySchemes", {}) if isinstance(doc.get("components"), dict) else {}
    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        for name in requirement:
            scheme = schemes.get(name) if isinstance(schemes, dict) else None
            if not isinstance(scheme, dict):
                continue
            kind = scheme.get("type")
            if kind == "http" and scheme.get("scheme", "").lower() == "bearer":
                return {"Authorization": "Bearer invalid-rivet-test-token"}
            if kind == "http" and scheme.get("scheme", "").lower() == "basic":
                return {"Authorization": "Basic aW52YWxpZDp0ZXN0"}
            if kind in {"oauth2", "openIdConnect"}:
                return {"Authorization": "Bearer invalid-rivet-test-token"}
            if kind == "apiKey" and scheme.get("in") == "header" and isinstance(scheme.get("name"), str):
                return {scheme["name"][:100]: "invalid-rivet-test-key"}
    return {}


def _has_refs(document: dict) -> bool:
    pending = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "$ref" in value:
                return True
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return False


def run_safe_api_tests(base_url: str, schema_path: Path, allowed_hosts: tuple[str, ...]) -> tuple[list[Finding], list[Check]]:
    """Probe documented safe routes only. No redirects, writes, or response bodies are retained."""
    try:
        if schema_path.is_symlink() or not schema_path.is_file() or schema_path.stat().st_size > MAX_SCHEMA_BYTES:
            raise ValueError("OpenAPI JSON must be a local regular file under the size limit")
        document = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("OpenAPI JSON is invalid or unavailable") from exc
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("OpenAPI JSON must contain a paths object")
    has_refs = _has_refs(document)
    base, host, address = _target(base_url, allowed_hosts)
    if base.query:
        raise ValueError("base URL must not contain a query")
    operations = []
    operations_truncated = False
    paths = document["paths"]
    for route, path_item in sorted(paths.items()):
        if not isinstance(route, str) or not route.startswith("/") or route.startswith("//") or any(ch in route for ch in "\r\n?#\\") or len(route) > 1000 or not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            method = method.upper() if isinstance(method, str) else ""
            if method not in SAFE_METHODS or not isinstance(operation, dict):
                continue
            if len(operations) >= MAX_OPERATIONS:
                operations_truncated = True
                break
            operations.append((route, method, path_item, operation))
        if operations_truncated:
            break
    if not operations:
        return [], [Check("Safe API testing", "SKIPPED", "W.Audit OpenAPI probes", "no documented GET/HEAD operations")]

    connection_class = _PinnedHTTPS if base.scheme == "https" else _PinnedHTTP
    port = base.port or (443 if base.scheme == "https" else 80)
    host_header = f"[{host}]" if ":" in host else host
    if base.port:
        host_header += f":{port}"
    base_path = base.path.rstrip("/")
    findings: list[Finding] = []
    requests_sent = 0
    failed_requests = 0
    redirects_seen = 0
    cross_origin_redirects = 0
    truncated = operations_truncated
    seen: set[tuple[str, str]] = set()

    def request(route: str, method: str, headers: dict[str, str] | None = None, body: bytes | None = None) -> tuple[int, object] | None:
        nonlocal requests_sent, truncated, failed_requests, redirects_seen, cross_origin_redirects
        if requests_sent >= MAX_REQUESTS:
            truncated = True
            return None
        requests_sent += 1
        connection = connection_class(host, port, str(address))
        try:
            path = base_path + route
            connection.request(method, path, body=body, headers={"Host": host_header, "User-Agent": "W.Audit/0.4.0b1 safe-api-probe", **(headers or {})})
            response = connection.getresponse()
            status, response_headers = response.status, response.headers
            response.read(MAX_RESPONSE_BYTES + 1)
            if 300 <= status < 400:
                location = response_headers.get("Location")
                if location:
                    redirects_seen += 1
                    try:
                        target = urlsplit(urljoin(base.geturl(), location))
                        target_port = target.port or (443 if target.scheme == "https" else 80)
                        if (target.scheme.lower(), (target.hostname or "").lower(), target_port) != (base.scheme.lower(), host.lower(), port):
                            cross_origin_redirects += 1
                    except ValueError:
                        cross_origin_redirects += 1
            return status, response_headers
        except (OSError, TimeoutError, ValueError, http.client.HTTPException, ssl.SSLError):
            failed_requests += 1
            return None
        finally:
            connection.close()

    def add(rule: str, title: str, severity: str, route: str, evidence: str, cwe: str) -> None:
        key = (rule, route)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(rule, title, severity, "MEDIUM", "Authentication" if "auth" in rule else "HTTP headers" if "header" in rule or "cors" in rule else "Input validation", route, 1, evidence, "The response suggests a documented security control may not be enforced.", "Confirm the behavior against the API's intended policy and enforce the control server-side.", "Repeat the probe in a dedicated test environment and verify the expected rejection or header.", "W.Audit safe OpenAPI probe", cwe, "CONDITIONAL", "NEEDS_MANUAL_REVIEW"))

    for route, method, path_item, operation in operations:
        parameters = []
        for items in (path_item.get("parameters", []), operation.get("parameters", [])):
            if isinstance(items, list):
                parameters.extend(item for item in items if isinstance(item, dict))
        path_params = {str(item.get("name")): item for item in parameters if item.get("in") == "path" and isinstance(item.get("name"), str)}
        invalid_uuid = False
        expanded = route
        for match in re.finditer(r"\{([^{}]+)\}", route):
            param = path_params.get(match.group(1), {})
            value = _sample(param)
            if isinstance(param.get("schema"), dict) and param["schema"].get("format") == "uuid":
                invalid_uuid = True
            expanded = expanded.replace("{" + match.group(1) + "}", value)
        query = {item["name"]: _sample(item) for item in parameters if item.get("in") == "query" and item.get("required") is True and isinstance(item.get("name"), str)}
        if query:
            expanded += "?" + urlencode(query)
        if len(expanded) > 2000 or "{" in expanded or "}" in expanded:
            continue
        security = operation.get("security", document.get("security", []))
        security = security if isinstance(security, list) else []
        requires_auth = bool(security)
        baseline = request(expanded, method)
        if baseline:
            status, headers = baseline
            if status >= 300 and status < 400:
                pass  # Inspect the response only; the pinned client never follows Location.
            else:
                if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
                    add("api/header-nosniff", "API response lacks X-Content-Type-Options: nosniff", "LOW", route, "safe API response lacks nosniff", "CWE-693")
                if base.scheme == "https" and not headers.get("Strict-Transport-Security"):
                    add("api/header-hsts", "HTTPS API response lacks Strict-Transport-Security", "LOW", route, "HTTPS response lacks HSTS", "CWE-319")
        if requires_auth and baseline and baseline[0] < 300:
            add("api/auth-missing", "Documented authentication did not reject an unauthenticated request", "MEDIUM", route, f"OpenAPI declares security; {method} returned HTTP {baseline[0]} without credentials", "CWE-306")
        if requires_auth:
            invalid = _invalid_auth(document, security)
            if invalid:
                result = request(expanded, method, invalid)
                if result and result[0] < 300:
                    add("api/auth-invalid", "Documented authentication accepted invalid credentials", "MEDIUM", route, f"OpenAPI declares security; {method} returned HTTP {result[0]} for invalid credentials", "CWE-287")
        if invalid_uuid:
            bad_path = re.sub(r"\{([^{}]+)\}", lambda m: "not-a-valid-uuid" if isinstance(path_params.get(m.group(1), {}).get("schema"), dict) and path_params[m.group(1)]["schema"].get("format") == "uuid" else _sample(path_params.get(m.group(1), {})), route)
            bad = request(bad_path, method)
            if bad and bad[0] < 300:
                add("api/uuid-validation", "API accepted an invalid UUID path parameter", "MEDIUM", route, f"{method} returned HTTP {bad[0]} for malformed UUID", "CWE-20")
        if method == "GET" and operation.get("x-rivet-read-only") is True:
            request_body = operation.get("requestBody") if isinstance(operation.get("requestBody"), dict) else {}
            media = request_body.get("content") if isinstance(request_body.get("content"), dict) else {}
            if "application/json" in media:
                wrong_type = request(expanded, method, {"Content-Type": "text/plain"}, b"rivet-test")
                if wrong_type and wrong_type[0] < 300:
                    add("api/content-type", "Read-only API operation accepted an unexpected content type", "LOW", route, f"GET returned HTTP {wrong_type[0]} with text/plain", "CWE-436")
                malformed = request(expanded, method, {"Content-Type": "application/json"}, b"{")
                if malformed and malformed[0] < 300:
                    add("api/malformed-json", "Read-only API operation accepted malformed JSON", "MEDIUM", route, f"GET returned HTTP {malformed[0]} for bounded malformed JSON", "CWE-20")
        cors = request(expanded, "OPTIONS", {"Origin": "https://rivet.invalid", "Access-Control-Request-Method": method, "Access-Control-Request-Headers": "authorization,content-type"})
        if cors:
            cors_headers = cors[1]
            if cors_headers.get("Access-Control-Allow-Origin") == "*" and cors_headers.get("Access-Control-Allow-Credentials", "").lower() == "true":
                add("api/cors-wildcard-credentials", "CORS preflight combines wildcard origin and credentials", "MEDIUM", route, "OPTIONS response advertises wildcard origin and credentials", "CWE-942")

    detail = f"{requests_sent} bounded requests; GET/HEAD and OPTIONS only; no redirects; 5-second timeout; response bodies discarded; maximum response read {MAX_RESPONSE_BYTES} bytes"
    if truncated:
        detail += "; request-count cap reached"
    if has_refs:
        detail += "; OpenAPI references were not dereferenced"
    if failed_requests:
        detail += f"; {failed_requests} requests failed"
    if redirects_seen:
        detail += f"; observed {redirects_seen} redirect Location value(s), {cross_origin_redirects} cross-origin; none followed"
    route_model = []
    scopes_by_operation: list[tuple[str, str, set[str]]] = []
    for route, method, _, operation in operations:
        security = operation.get("security", document.get("security", []))
        scopes = {scope.upper() for requirement in security if isinstance(requirement, dict) for values in requirement.values() if isinstance(values, list) for scope in values if isinstance(scope, str)} if isinstance(security, list) else set()
        scopes_by_operation.append((route, method, scopes))
        route_model.append({"method": method, "path": route, "endpoint": f"{method} {route}", "file": schema_path.name, "line": 1, "authentication": "INFERRED" if security else "UNKNOWN", "authorization": "INFERRED" if scopes else "UNKNOWN", "resource": route.split("/")[1] if "/" in route else "UNKNOWN", "action": {"GET": "READ", "HEAD": "READ"}.get(method, "UNKNOWN"), "required_role": sorted(scopes)[0] if scopes else "UNKNOWN", "evidence_status": "INFERRED", "bola_class": "UNKNOWN"})
    all_roles = sorted({role for _, _, scopes in scopes_by_operation for role in scopes})
    role_rows = [{"role": role, "endpoint": route, "method": method, "status": "INFERRED" if role in scopes else "UNKNOWN", "evidence_status": "INFERRED"} for route, method, scopes in scopes_by_operation for role in all_roles]
    return findings, [Check("Safe API testing", "PARTIAL" if truncated or failed_requests or has_refs else "CHECKED", "W.Audit OpenAPI probes", detail)], route_model, role_rows
