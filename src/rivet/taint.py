from __future__ import annotations

import ast
from pathlib import Path
import time

from .model import Finding

SOURCES = {
    "request.args.get", "request.form.get", "request.json.get", "request.values.get",
    "request.query_params.get", "request.GET.get", "request.POST.get", "request.headers.get",
    "request.cookies.get", "request.files.get", "request.FILES.get", "request.body.get",
}
VALIDATORS = {"int", "float", "uuid.UUID", "UUID", "os.path.basename"}
MAX_PROJECT_FILES = 100
MAX_PROJECT_NODES = 10_000
MAX_PROJECT_SOURCE_CHARS = 20_000_000
PROJECT_TIMEOUT = 0.25


def _name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _source_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call) and _name(node.func) in SOURCES:
        return _name(node.func)
    if isinstance(node, ast.Subscript) and _name(node.value) in {"request.args", "request.form", "request.json", "request.GET", "request.POST", "request.query_params", "request.headers", "request.cookies", "request.files", "request.FILES"}:
        return _name(node.value) + "[]"
    return None


def _trace(node: ast.AST, env: dict[str, str]) -> str | None:
    source = _source_name(node)
    if source:
        return source
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.Call):
        name = _name(node.func)
        if name in VALIDATORS or (name.endswith(".name") and name.startswith("Path")):
            return None
        children = list(node.args) + [kw.value for kw in node.keywords]
        if isinstance(node.func, ast.Attribute):
            children.append(node.func.value)
        for child in children:
            trace = _trace(child, env)
            if trace:
                return trace + f" → {name or 'call'}"
        return None
    for child in ast.iter_child_nodes(node):
        trace = _trace(child, env)
        if trace:
            return trace
    return None


def _sink(call: ast.Call) -> tuple[str, str, str, str] | None:
    name = _name(call.func)
    if not call.args:
        return None
    if name.endswith(".execute") or name.endswith(".executemany"):
        return ("SQL injection", "CWE-89", "Use parameterized SQL with bound values.", name)
    if name in {"os.system", "os.popen"}:
        return ("Command injection", "CWE-78", "Use an argument array and avoid a shell.", name)
    if name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"} and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in call.keywords):
        return ("Command injection", "CWE-78", "Use shell=False and an argument array.", name)
    if name in {"open", "io.open", "Path", "pathlib.Path"}:
        return ("Path traversal", "CWE-22", "Resolve against an allowed directory and enforce containment.", name)
    if name in {"render_template_string", "flask.render_template_string"}:
        return ("Template injection", "CWE-1336", "Use a fixed template and pass input as data.", name)
    if name in {"redirect", "flask.redirect"}:
        return ("Open redirect", "CWE-601", "Allowlist redirect destinations.", name)
    if name in {"requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen"}:
        return ("SSRF", "CWE-918", "Allowlist destinations and block private and metadata addresses.", name)
    return None


def _route_inputs(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
    decorators = [_name(d.func) if isinstance(d, ast.Call) else _name(d) for d in node.decorator_list]
    if not any(d.endswith((".get", ".post", ".put", ".patch", ".delete", ".route")) for d in decorators):
        return {}
    result = {}
    defaults = [None] * (len(node.args.args) - len(node.args.defaults)) + list(node.args.defaults)
    for arg, default in zip(node.args.args, defaults):
        if arg.arg in {"self", "request", "db", "session", "current_user"}:
            continue
        if isinstance(default, ast.Call) and _name(default.func).endswith("Depends"):
            continue
        result[arg.arg] = f"route parameter {arg.arg}"
    return result


def scan_python_flows(rel: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    findings = []
    functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    deadline = time.monotonic() + 0.2
    visited = 0

    def visit(function: ast.FunctionDef | ast.AsyncFunctionDef, initial: dict[str, str], stack: tuple[str, ...]) -> None:
        nonlocal visited
        if len(stack) > 5 or visited > 10000 or time.monotonic() > deadline:
            return
        env = dict(initial)
        for statement in function.body:
            visited += 1
            if visited > 10000 or time.monotonic() > deadline:
                return
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                trace = _trace(value, env) if value else None
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        if trace:
                            env[target.id] = trace + f" → {target.id}"
                        else:
                            env.pop(target.id, None)
            for call in (item for item in ast.walk(statement) if isinstance(item, ast.Call)):
                callee_name = _name(call.func)
                callee = functions.get(callee_name)
                if callee is not None and callee_name not in stack:
                    passed = {}
                    for arg, value in zip(callee.args.args, call.args):
                        trace = _trace(value, env)
                        if trace:
                            passed[arg.arg] = trace + f" → {callee_name}"
                    for keyword in call.keywords:
                        if keyword.arg:
                            trace = _trace(keyword.value, env)
                            if trace:
                                passed[keyword.arg] = trace + f" → {callee_name}"
                    if passed:
                        visit(callee, passed, stack + (callee_name,))
                sink = _sink(call)
                if sink is None:
                    continue
                category, cwe, fix, sink_name = sink
                trace = _trace(call.args[0], env)
                if not trace:
                    continue
                # Bound SQL parameters do not make a constant query string attacker-controlled.
                evidence = f"REACHABLE FLOW: {trace} → {sink_name}"
                findings.append(Finding("python/flow/" + category.lower().replace(" ", "-"), f"Untrusted input reaches {sink_name}", "MEDIUM", "HIGH", category, rel, getattr(call, "lineno", 1), evidence, "Untrusted request data may affect this sensitive operation; review validation and context.", fix, "Trace the request value in a test and confirm the boundary rejects unsafe input.", "Rivet AST flow", cwe, "LIKELY", "NEEDS_MANUAL_REVIEW", "REACHABLE_FLOW", evidence, "Данные из запроса доходят до опасной операции. Проверьте, что ввод ограничен и проверен."))
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        visit(function, _route_inputs(function), (function.name,))
    return findings


def scan_python_project(texts: dict[str, str]) -> tuple[list[Finding], bool]:
    """Bounded local-import flow tracing; returns findings and a truncation flag."""
    deadline = time.monotonic() + PROJECT_TIMEOUT
    paths = sorted(path for path in texts if path.endswith(".py"))
    truncated = len(paths) > MAX_PROJECT_FILES
    paths = paths[:MAX_PROJECT_FILES]
    accepted: list[str] = []
    source_chars = 0
    for path in paths:
        if time.monotonic() > deadline:
            truncated = True
            break
        source_chars += len(texts[path])
        if source_chars > MAX_PROJECT_SOURCE_CHARS:
            truncated = True
            break
        accepted.append(path)
    paths = accepted
    trees: dict[str, ast.Module] = {}
    functions: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    modules: dict[str, str] = {}
    module_files: dict[str, str] = {}
    imports: dict[str, dict[str, tuple[str, str]]] = {}

    for path in paths:
        if time.monotonic() > deadline:
            truncated = True
            break
        try:
            tree = ast.parse(texts[path])
        except (SyntaxError, RecursionError, ValueError):
            truncated = True
            continue
        trees[path] = tree
        parts = list(Path(path).with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        module = ".".join(parts)
        modules[path] = module
        module_files[module] = path
        functions[path] = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def module_path(name: str) -> str | None:
        return module_files.get(name) or module_files.get(name + ".__init__")

    for path, tree in trees.items():
        table: dict[str, tuple[str, str]] = {}
        current = modules[path]
        package = current.rpartition(".")[0] if not path.endswith("/__init__.py") else current
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    target = alias.name if alias.asname else alias.name.split(".", 1)[0]
                    if module_path(target):
                        table[local] = ("module", target)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = package.split(".") if package else []
                    base = base[:max(0, len(base) - node.level + 1)]
                    mod = ".".join(base + ([node.module] if node.module else []))
                else:
                    mod = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    target_module = mod
                    target_file = module_path(target_module)
                    if target_file and alias.name in functions.get(target_file, {}):
                        table[local] = ("function", target_file + ":" + alias.name)
                    elif module_path(".".join(filter(None, (mod, alias.name)))):
                        table[local] = ("module", ".".join(filter(None, (mod, alias.name))))
                    elif target_file:
                        table[local] = ("function", target_file + ":" + alias.name)
        imports[path] = table

    findings: list[Finding] = []
    reported: set[tuple[str, int, str]] = set()
    visited = 0
    active: set[tuple[str, str, tuple[str, ...]]] = set()

    def resolve_call(path: str, call: ast.Call) -> tuple[str, str] | None:
        name = _name(call.func)
        if not name:
            return None
        head, _, tail = name.partition(".")
        target = imports.get(path, {}).get(head)
        if target:
            if target[0] == "function":
                file, _, function = target[1].partition(":")
                if not tail and function in functions.get(file, {}):
                    return file, function
            else:
                combined = target[1].split(".") + (tail.split(".") if tail else [])
                for split in range(len(combined) - 1, 0, -1):
                    file = module_path(".".join(combined[:split]))
                    function = ".".join(combined[split:])
                    if file and function in functions.get(file, {}):
                        return file, function
        if name in functions.get(path, {}):
            return path, name
        if "." in name and module_path(name.rpartition(".")[0]):
            file = module_path(name.rpartition(".")[0])
            function = name.rpartition(".")[2]
            if file and function in functions.get(file, {}):
                return file, function
        return None

    def visit(path: str, function_name: str, initial: dict[str, str], stack: tuple[str, ...]) -> list[str]:
        nonlocal visited, truncated
        if len(stack) > 5 or time.monotonic() > deadline or visited >= MAX_PROJECT_NODES:
            truncated = True
            return []
        key = (path, function_name, stack)
        if key in active:
            return []
        function = functions.get(path, {}).get(function_name)
        if function is None:
            return []
        active.add(key)
        env = dict(initial)
        returns: list[str] = []

        def trace(node: ast.AST | None) -> str | None:
            if node is None:
                return None
            source = _source_name(node)
            if source:
                return source
            if isinstance(node, ast.Name):
                return env.get(node.id)
            if isinstance(node, ast.Call):
                callee = resolve_call(path, node)
                if callee:
                    passed: dict[str, str] = {}
                    target = functions.get(callee[0], {}).get(callee[1])
                    if target:
                        for arg, value in zip(target.args.args, node.args):
                            value_trace = trace(value)
                            if value_trace:
                                passed[arg.arg] = value_trace + f" → {callee[1]}"
                        for kw in node.keywords:
                            if kw.arg:
                                value_trace = trace(kw.value)
                                if value_trace:
                                    passed[kw.arg] = value_trace + f" → {callee[1]}"
                    returned = visit(callee[0], callee[1], passed, stack + (callee[1],)) if passed else []
                    if returned:
                        return returned[0] + f" → {callee[1]} return"
                for child in list(node.args) + [kw.value for kw in node.keywords]:
                    value_trace = trace(child)
                    if value_trace:
                        return value_trace + f" → {_name(node.func) or 'call'}"
                return None
            return _trace(node, env)

        for statement in function.body:
            if visited >= MAX_PROJECT_NODES or time.monotonic() > deadline:
                truncated = True
                break
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                value_trace = trace(value)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        if value_trace:
                            env[target.id] = value_trace + f" → {target.id}"
                        else:
                            env.pop(target.id, None)
            if isinstance(statement, ast.Return):
                value_trace = trace(statement.value)
                if value_trace:
                    returns.append(value_trace)
            for node in ast.walk(statement):
                visited += 1
                if visited >= MAX_PROJECT_NODES or time.monotonic() > deadline:
                    truncated = True
                    break
                if not isinstance(node, ast.Call):
                    continue
                call = node
                sink = _sink(call)
                if sink:
                    category, cwe, fix, sink_name = sink
                    flow = trace(call.args[0])
                    if flow:
                        identity = (path, getattr(call, "lineno", 1), cwe)
                        if identity in reported:
                            continue
                        reported.add(identity)
                        evidence = f"REACHABLE FLOW: {flow} → {sink_name}"
                        findings.append(Finding("python/flow/" + category.lower().replace(" ", "-"), f"Untrusted input reaches {sink_name}", "MEDIUM", "HIGH", category, path, getattr(call, "lineno", 1), evidence, "Untrusted request data may affect this sensitive operation; review validation and context.", fix, "Trace the request value in a test and confirm the boundary rejects unsafe input.", "Rivet bounded local-import flow", cwe, "LIKELY", "NEEDS_MANUAL_REVIEW", "REACHABLE_FLOW", evidence, "Данные из запроса доходят до опасной операции. Проверьте, что ввод ограничен и проверен."))
                callee = resolve_call(path, call)
                if callee:
                    target = functions.get(callee[0], {}).get(callee[1])
                    passed = {}
                    if target:
                        for arg, value in zip(target.args.args, call.args):
                            value_trace = trace(value)
                            if value_trace:
                                passed[arg.arg] = value_trace + f" → {callee[1]}"
                        for kw in call.keywords:
                            if kw.arg:
                                value_trace = trace(kw.value)
                                if value_trace:
                                    passed[kw.arg] = value_trace + f" → {callee[1]}"
                    if passed:
                        visit(callee[0], callee[1], passed, stack + (callee[1],))
        active.remove(key)
        return returns

    for path, tree in trees.items():
        for function in (n for n in functions.get(path, {}).values() if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            if visited >= MAX_PROJECT_NODES or time.monotonic() > deadline:
                truncated = True
                break
            try:
                inputs = _route_inputs(function)
                if inputs:
                    visit(path, function.name, inputs, (function.name,))
            except RecursionError:
                truncated = True
                break
    return findings, truncated
