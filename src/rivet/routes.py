from __future__ import annotations

import ast
import re

from .model import Finding


def _name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _route(decorator: ast.AST) -> tuple[str, str] | None:
    if not isinstance(decorator, ast.Call) or not decorator.args or not isinstance(decorator.args[0], ast.Constant) or not isinstance(decorator.args[0].value, str):
        return None
    method = _name(decorator.func).split(".")[-1].upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "ROUTE"}:
        return None
    path = decorator.args[0].value[:300]
    if method == "ROUTE":
        method = "GET"
        for kw in decorator.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)) and kw.value.elts:
                first = kw.value.elts[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    method = first.value.upper()
    return method, path


def _auth_flags(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str]:
    names = {_name(node.func).lower() for node in ast.walk(function) if isinstance(node, ast.Call)}
    decorators = {_name(node.func if isinstance(node, ast.Call) else node).lower() for node in function.decorator_list}
    used_names = {node.id.lower() for node in ast.walk(function) if isinstance(node, ast.Name)}
    auth = bool(used_names & {"current_user", "authenticated_user", "get_current_user"}) or any(name.endswith(("get_current_user", "login_required", "auth_required", "authenticate", "is_authenticated")) for name in names | decorators)
    authorization = any(name.endswith(("check_owner", "has_permission", "authorize", "check_permission", "require_role", "permission_required", "roles_required")) for name in names | decorators)
    for node in ast.walk(function):
        if not isinstance(node, ast.Compare):
            continue
        expression = ast.unparse(node).lower()
        if ("owner_id" in expression or "tenant_id" in expression) and ("current_user" in expression or "request.user" in expression):
            authorization = True
    return ("INFERRED" if auth else "UNKNOWN", "INFERRED" if authorization else "UNKNOWN")


def _required_role(function: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    for node in list(function.decorator_list) + list(ast.walk(function)):
        if isinstance(node, ast.Call) and _name(node.func).lower().endswith(("require_role", "roles_required", "require_permission", "permission_required")) and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            return node.args[0].value[:80].upper()
        if isinstance(node, ast.Call) and _name(node.func).lower().endswith("depends") and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id.lower().startswith("require_"):
            return node.args[0].id[8:88].upper()
    return "UNKNOWN"


def analyze_python_routes(rel: str, text: str) -> tuple[list[dict], list[Finding]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], []
    routes, findings = [], []
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        auth, authorization = _auth_flags(function)
        for decorator in function.decorator_list:
            route = _route(decorator)
            if route is None:
                continue
            method, path = route
            required_role = _required_role(function)
            action = {"GET": "READ", "HEAD": "READ", "POST": "CREATE", "PUT": "UPDATE", "PATCH": "UPDATE", "DELETE": "DELETE"}.get(method, "UNKNOWN")
            route = {"method": method, "path": path, "endpoint": f"{method} {path}", "function": function.name, "file": rel, "line": function.lineno, "authentication": auth, "authorization": authorization, "resource": path.split("/")[1] if "/" in path and len(path.split("/")) > 1 else "UNKNOWN", "action": action, "required_role": required_role, "evidence_status": "INFERRED", "bola_class": "UNKNOWN"}
            routes.append(route)
            id_param = re.search(r"(?:\{|<[^:>]*:?)([A-Za-z_]*(?:id|uuid))\b", path, re.I)
            if method not in {"GET", "PATCH", "PUT", "DELETE"} or id_param is None or authorization != "UNKNOWN":
                continue
            parameter = id_param.group(1)
            if not any(isinstance(node, ast.Name) and node.id == parameter for node in ast.walk(function)):
                continue
            bola_class = "POSSIBLE_BOLA"
            resource_results = set()
            for statement in ast.walk(function):
                if isinstance(statement, (ast.Assign, ast.AnnAssign)) and isinstance(statement.value, ast.Call):
                    call = statement.value
                    call_name = _name(call.func).lower()
                    if call_name.endswith((".get", ".first", ".one", ".delete", ".update")) and any(isinstance(item, ast.Name) and item.id == parameter for item in ast.walk(call)):
                        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                        resource_results.update(item.id for item in targets if isinstance(item, ast.Name))
                if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Call):
                    call_name = _name(statement.value.func).lower()
                    if call_name.endswith((".get", ".first", ".one", ".delete", ".update")) and any(isinstance(item, ast.Name) and item.id == parameter for item in ast.walk(statement.value)):
                        bola_class = "LIKELY_BOLA"
                elif isinstance(statement, ast.Return) and isinstance(statement.value, ast.Name) and statement.value.id in resource_results:
                    bola_class = "LIKELY_BOLA"
            route["bola_class"] = bola_class
            findings.append(Finding("authz/bola-candidate", "Object authorization needs review", "MEDIUM", "LOW", "Authorization", rel, function.lineno, f"{bola_class}: {method} {path} uses resource identifier {parameter}; ownership check not recognized", "A user may try another resource ID if server-side ownership checks are absent.", "Verify object ownership or permission in the backend before returning or mutating it.", "Use two users in a test environment and confirm cross-user access is denied.", "W.Audit route analysis", "CWE-639", "THEORETICAL", "NEEDS_MANUAL_REVIEW", "PATTERN_DETECTED", "Route and resource identifier found; authorization heuristic is incomplete.", "Если заменить ID в запросе, доступ к чужому объекту должен быть запрещён сервером."))
    return routes, findings


def build_authorization_matrix(routes: list[dict]) -> list[dict]:
    roles = sorted({route["required_role"] for route in routes if route.get("required_role") not in {"UNKNOWN", ""}})
    return [{"role": role, "endpoint": route["path"], "method": route["method"], "status": "INFERRED" if route.get("required_role") == role else "UNKNOWN", "evidence_status": "INFERRED"} for route in routes for role in roles]
