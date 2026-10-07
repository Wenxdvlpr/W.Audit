from __future__ import annotations

import ast

from .model import Finding


def _name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _ai_output(node: ast.AST, names: set[str]) -> bool:
    if isinstance(node, ast.Name) and node.id in names:
        return True
    if isinstance(node, ast.Attribute) and node.attr in {"output_text", "content", "text"}:
        expression = ast.unparse(node).lower()
        if any(marker in expression for marker in ("response", "completion", "message", "result")):
            return True
    if isinstance(node, ast.Call) and _name(node.func).endswith((".invoke", ".generate", ".responses.create", ".completions.create")):
        return True
    return any(_ai_output(child, names) for child in ast.iter_child_nodes(node))


def _sink(call: ast.Call) -> tuple[str, str] | None:
    name = _name(call.func)
    if name in {"os.system", "os.popen"}:
        return "ai/output-to-shell", "shell command"
    if name in {"subprocess.run", "subprocess.Popen", "subprocess.call"} and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in call.keywords):
        return "ai/output-to-shell", "shell command"
    if name.endswith(".execute"):
        return "ai/output-to-sql", "SQL query"
    if name in {"open", "Path", "pathlib.Path"} or name.endswith(".write_text"):
        return "ai/output-to-file", "filesystem operation"
    if name in {"render_template_string", "flask.render_template_string"}:
        return "ai/output-to-html", "HTML template"
    return None


def scan_python_ai(rel: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    findings = []
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        name = _name(call.func)
        for keyword in call.keywords:
            if keyword.arg in {"trust_remote_code", "allow_dangerous_deserialization"} and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                rule = "ai/trust-remote-code" if keyword.arg == "trust_remote_code" else "ai/dangerous-deserialization"
                findings.append(Finding(rule, "AI component enables unsafe code or data loading", "MEDIUM", "HIGH", "AI supply chain", rel, call.lineno, f"{keyword.arg}=True", "Untrusted model or index files may execute code during loading.", "Disable the unsafe option and verify model or index provenance.", "Load a vetted artifact with the unsafe option disabled.", "Rivet AST", "CWE-502", "CONDITIONAL", "NEEDS_MANUAL_REVIEW"))
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        ai_names: set[str] = set()
        for statement in function.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value:
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        if _ai_output(statement.value, ai_names):
                            ai_names.add(target.id)
                        else:
                            ai_names.discard(target.id)
            for call in (node for node in ast.walk(statement) if isinstance(node, ast.Call)):
                sink = _sink(call)
                if sink is None or not call.args or not _ai_output(call.args[0], ai_names):
                    continue
                rule, destination = sink
                cwe = {"ai/output-to-shell": "CWE-78", "ai/output-to-sql": "CWE-89", "ai/output-to-file": "CWE-22", "ai/output-to-html": "CWE-79"}[rule]
                findings.append(Finding(rule, "AI output reaches sensitive operation", "MEDIUM", "MEDIUM", "AI/LLM", rel, call.lineno, f"AI response → {_name(call.func)}; local flow detected", f"Model output may control a {destination} if not validated.", "Treat model output as untrusted data; validate and constrain the destination.", "Use a malicious model response in an isolated test and confirm it is rejected.", "Rivet AI AST", cwe, "CONDITIONAL", "NEEDS_MANUAL_REVIEW", "REACHABLE_FLOW", "Local AI response variable reaches a sensitive API; external trust boundary needs confirmation.", "Ответ модели попадает в опасную операцию. Проверяйте и ограничивайте такие данные."))
    return findings
