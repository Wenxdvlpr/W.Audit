from __future__ import annotations

import ast
from pathlib import Path
import re

from .model import Finding, Check
from .secrets import scan_secrets
from .taint import scan_python_project
from .auth import scan_python_auth
from .ai import scan_python_ai
from .mcp import scan_mcp_config


def make(rule, title, severity, confidence, category, path, line, evidence, impact, fix, verify, scanner="rivet", cwe="", exploitability="CONDITIONAL"):
    return Finding(rule, title, severity, confidence, category, path, line, evidence, impact, fix, verify, scanner, cwe, exploitability, "NEEDS_MANUAL_REVIEW")


def _call_name(node: ast.Call) -> str:
    parts = []
    value = node.func
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def scan_python(rel: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    result = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        line = getattr(node, "lineno", 1)
        if name in {"os.system", "os.popen"}:
            result.append(make("python/os-shell", "Shell command execution", "MEDIUM", "HIGH", "Command injection", rel, line, f"Call to {name}", "If input reaches the command string, an attacker may execute commands.", "Use an argument array with subprocess and validate each argument.", "Trace all inputs to this call and test hostile metacharacters.", cwe="CWE-78"))
        if name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"} and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
            result.append(make("python/subprocess-shell", "Subprocess uses shell=True", "MEDIUM", "HIGH", "Command injection", rel, line, "shell=True", "Untrusted arguments may be interpreted by a shell.", "Use shell=False and a fixed argument array.", "Check call sites and rerun tests with hostile input.", cwe="CWE-78"))
        if name in {"pickle.loads", "pickle.load", "yaml.unsafe_load"}:
            result.append(make("python/unsafe-deserialization", "Unsafe deserialization API", "MEDIUM", "HIGH", "Deserialization", rel, line, f"Call to {name}", "Attacker-controlled serialized data may execute code.", "Use a safe data format and reject untrusted serialized objects.", "Trace input provenance and test rejection of untrusted payloads.", cwe="CWE-502"))
        if name == "yaml.load" and not any(k.arg == "Loader" and isinstance(k.value, ast.Attribute) and k.value.attr == "SafeLoader" for k in node.keywords):
            result.append(make("python/yaml-load", "YAML load without explicit SafeLoader", "MEDIUM", "MEDIUM", "Deserialization", rel, line, "yaml.load call", "Unsafe loaders can construct Python objects from untrusted YAML.", "Use yaml.safe_load for untrusted data.", "Verify untrusted YAML cannot instantiate objects.", cwe="CWE-502"))
        if name in {"eval", "exec"}:
            result.append(make("python/eval", "Dynamic Python evaluation", "MEDIUM", "MEDIUM", "Code execution", rel, line, f"Call to {name}", "Untrusted input can become executable Python.", "Replace evaluation with a parser for the required data format.", "Trace input provenance and test rejection of code payloads.", cwe="CWE-95"))
        if name.endswith(".execute") and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
            result.append(make("python/dynamic-sql", "SQL query built with string interpolation", "MEDIUM", "MEDIUM", "SQL injection", rel, line, "Interpolated SQL passed to execute", "User input may alter SQL when it reaches this expression.", "Use parameterized queries; allowlist dynamic identifiers.", "Trace input to query and test injection cases.", cwe="CWE-89"))
    return result


JS_PATTERNS = [
    (re.compile(r"\b(?:eval|Function)\s*\("), "js/eval", "Dynamic JavaScript execution", "Code execution", "CWE-95"),
    (re.compile(r"\b(?:innerHTML|outerHTML)\s*="), "js/html-sink", "HTML injection sink", "XSS", "CWE-79"),
    (re.compile(r"\bdangerouslySetInnerHTML\b"), "js/react-html-sink", "React raw HTML sink", "XSS", "CWE-79"),
    (re.compile(r"\bchild_process\.exec\s*\("), "js/exec", "Shell command execution", "Command injection", "CWE-78"),
]


def scan_js(rel: str, text: str) -> list[Finding]:
    result = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("//", "*", "#")):
            continue
        for pattern, rule, title, category, cwe in JS_PATTERNS:
            if pattern.search(line):
                result.append(make(rule, title, "MEDIUM", "LOW", category, rel, line_no, f"Use of {rule.split('/')[-1]} sink", "Untrusted input at this sink can cross a security boundary.", "Validate input and use a safe API or escaping appropriate to the output context.", "Trace the input source and add a negative test.", cwe=cwe, exploitability="THEORETICAL"))
    return result


def scan_config(rel: str, text: str) -> list[Finding]:
    result = []
    name = Path(rel).name
    dockerfile = name.startswith("Dockerfile")
    compose = name in {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
    workflow = rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml"))
    kubernetes = rel.endswith((".yml", ".yaml")) and ("kind: Deployment" in text or "kind: Pod" in text or "/k8s/" in f"/{rel}" or "/kubernetes/" in f"/{rel}")
    if workflow and re.search(r"\bpull_request_target\b", text) and re.search(r"\buses:\s*actions/checkout@", text):
        line = next((i for i, value in enumerate(text.splitlines(), 1) if "pull_request_target" in value), 1)
        result.append(make("ci/pull-request-target-checkout", "Privileged PR workflow checks out code", "MEDIUM", "MEDIUM", "CI supply chain", rel, line, "pull_request_target and actions/checkout coexist", "Untrusted PR code may run with a privileged token or secrets depending on checkout configuration.", "Avoid untrusted checkout in pull_request_target; split privileged and untrusted jobs.", "Review workflow token permissions and test an untrusted PR safely.", cwe="CWE-829", exploitability="CONDITIONAL"))
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if dockerfile and re.search(r"^FROM\s+[^#\s]+:latest(?:\s|$)", stripped, re.I):
            result.append(make("docker/latest", "Docker base image uses mutable latest tag", "LOW", "HIGH", "Supply chain", rel, line_no, "FROM image:latest", "Build inputs can change without a source change.", "Pin an image digest or immutable release tag.", "Build twice and confirm identical base digest.", cwe="CWE-1104"))
        if dockerfile and re.search(r"^USER\s+root(?:\s|$)", stripped, re.I):
            result.append(make("docker/root", "Container explicitly runs as root", "MEDIUM", "HIGH", "Container", rel, line_no, "USER root", "A compromised process has more privileges inside the container.", "Create a dedicated unprivileged user.", "Inspect the runtime UID.", cwe="CWE-250"))
        if compose and re.search(r"\bprivileged:\s*true\b", stripped, re.I):
            result.append(make("compose/privileged", "Compose service is privileged", "MEDIUM", "HIGH", "Container", rel, line_no, "privileged: true", "The service gains broad host-facing capabilities.", "Remove privileged mode and grant only needed capabilities.", "Inspect container effective capabilities.", cwe="CWE-250"))
        if dockerfile and re.search(r"^RUN\s+.*\b(?:curl|wget)\b.*\|\s*(?:bash|sh)\b", stripped, re.I):
            result.append(make("docker/remote-shell", "Docker build pipes remote script into a shell", "MEDIUM", "HIGH", "Supply chain", rel, line_no, "RUN downloads and executes a script", "A changed remote script can execute during builds.", "Download a pinned artifact and verify its checksum before execution.", "Rebuild with a verified immutable source.", cwe="CWE-829"))
        if dockerfile and re.search(r"^ADD\s+https?://", stripped, re.I):
            result.append(make("docker/remote-add", "Docker ADD downloads a remote resource", "MEDIUM", "HIGH", "Supply chain", rel, line_no, "ADD remote URL", "Build input can change outside source control.", "Use a pinned download with checksum verification.", "Confirm source digest in build logs.", cwe="CWE-829"))
        if dockerfile and re.search(r"^RUN\s+.*\bchmod\s+(?:-R\s+)?777\b", stripped, re.I):
            result.append(make("docker/world-writable", "Docker build makes path world-writable", "MEDIUM", "HIGH", "Container", rel, line_no, "chmod 777", "Any process in the container may modify the path.", "Use the narrowest owner, group and mode required.", "Inspect resulting file permissions.", cwe="CWE-732"))
        if dockerfile and re.search(r"^(?:ENV|ARG)\s+[A-Z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY)[A-Z_]*[=\s]+\S+", stripped, re.I):
            result.append(make("docker/secret-env", "Credential set in Docker build instruction", "MEDIUM", "HIGH", "Secrets", rel, line_no, "ENV or ARG sets credential-like value; value redacted", "Build metadata or layers may expose the value.", "Use a runtime secret manager or BuildKit secret mount.", "Inspect image history and rotate any exposed credential.", cwe="CWE-798"))
        if compose and re.search(r"\bnetwork_mode:\s*host\b", stripped, re.I):
            result.append(make("compose/host-network", "Compose service uses host networking", "MEDIUM", "HIGH", "Container", rel, line_no, "network_mode: host", "Network isolation is reduced.", "Use isolated bridge networking and explicit ports.", "Inspect runtime network mode.", cwe="CWE-250"))
        if compose and "/var/run/docker.sock" in stripped:
            result.append(make("compose/docker-socket", "Docker socket mounted into service", "MEDIUM", "HIGH", "Container", rel, line_no, "Docker socket mount", "A compromised container may control the Docker host.", "Remove the socket mount or use a narrowly scoped proxy.", "Inspect service mounts.", cwe="CWE-250"))
        if compose and re.search(r"(?:0\.0\.0\.0:)?(?:5432|3306|27017|6379):(?:5432|3306|27017|6379)", stripped):
            result.append(make("compose/public-database", "Database port published from Compose", "MEDIUM", "MEDIUM", "Database", rel, line_no, "Database port mapping", "The database may be reachable beyond intended services.", "Remove the published port or bind only to loopback for local development.", "Check effective host bindings and firewall.", cwe="CWE-284"))
        if compose and re.search(r"\b(?:SYS_ADMIN|NET_ADMIN|ALL)\b", stripped) and "cap_add" in text:
            result.append(make("compose/dangerous-capability", "Compose grants broad Linux capability", "MEDIUM", "MEDIUM", "Container", rel, line_no, "cap_add includes broad capability", "A compromised service may gain excessive privileges.", "Remove broad capabilities and add only required ones.", "Inspect effective runtime capabilities.", cwe="CWE-250"))
        if workflow and re.search(r"\buses:\s*[^\s#]+@(?:main|master|latest|v\d+(?:\.\d+)*)\b", stripped):
            result.append(make("ci/unpinned-action", "GitHub Action reference is mutable", "LOW", "HIGH", "CI supply chain", rel, line_no, "Action uses tag or branch", "A changed upstream ref can alter CI behavior.", "Pin the action to a full commit SHA and use an update bot.", "Confirm the ref is a 40-character commit SHA.", cwe="CWE-829"))
        if workflow and re.search(r"\bpermissions:\s*write-all\b", stripped):
            result.append(make("ci/write-all", "Workflow grants write-all token permissions", "MEDIUM", "HIGH", "CI supply chain", rel, line_no, "permissions: write-all", "A compromised job can modify repository resources.", "Grant only the permissions each job needs.", "Inspect effective GITHUB_TOKEN permissions.", cwe="CWE-250"))
        if workflow and re.search(r"\bruns-on:\s*self-hosted\b", stripped):
            result.append(make("ci/self-hosted", "Workflow runs on self-hosted runner", "MEDIUM", "LOW", "CI supply chain", rel, line_no, "runs-on: self-hosted", "Untrusted PR code may persist or access host resources on a non-ephemeral runner.", "Use ephemeral isolated runners and restrict untrusted jobs.", "Review runner isolation and workflow triggers.", cwe="CWE-250", exploitability="THEORETICAL"))
        if workflow and "run:" in stripped and re.search(r"\$\{\{\s*github\.event\.", stripped):
            result.append(make("ci/event-shell-interpolation", "Untrusted event data interpolated into shell step", "MEDIUM", "HIGH", "CI injection", rel, line_no, "github.event expression in run step", "Attacker-controlled event text may alter shell commands.", "Pass event values through quoted environment variables and validate them.", "Test a PR title containing shell metacharacters in an isolated workflow.", cwe="CWE-78"))
        if kubernetes and re.search(r"\bhostNetwork:\s*true\b", stripped):
            result.append(make("k8s/host-network", "Kubernetes pod uses host networking", "MEDIUM", "HIGH", "Kubernetes", rel, line_no, "hostNetwork: true", "Pod gains access to host network namespace.", "Disable host networking unless required.", "Inspect deployed pod network settings.", cwe="CWE-250"))
        if kubernetes and re.search(r"\bprivileged:\s*true\b", stripped):
            result.append(make("k8s/privileged", "Kubernetes container is privileged", "MEDIUM", "HIGH", "Kubernetes", rel, line_no, "privileged: true", "Container gains broad host-facing privileges.", "Disable privileged mode and use a restricted security context.", "Inspect deployed securityContext.", cwe="CWE-250"))
        if kubernetes and re.search(r"\brunAsUser:\s*0\b", stripped):
            result.append(make("k8s/root-user", "Kubernetes container runs as root", "MEDIUM", "HIGH", "Kubernetes", rel, line_no, "runAsUser: 0", "Root inside the container increases impact of compromise.", "Set a nonzero UID and runAsNonRoot.", "Inspect effective UID.", cwe="CWE-250"))
        if kubernetes and re.search(r"\ballowPrivilegeEscalation:\s*true\b", stripped):
            result.append(make("k8s/privilege-escalation", "Kubernetes allows privilege escalation", "MEDIUM", "HIGH", "Kubernetes", rel, line_no, "allowPrivilegeEscalation: true", "A process may gain additional privileges.", "Set allowPrivilegeEscalation: false.", "Inspect deployed securityContext.", cwe="CWE-250"))
        if rel.endswith(".tf") and re.search(r"0\.0\.0\.0/0", stripped) and "#" not in stripped.split("0.0.0.0/0")[0]:
            result.append(make("terraform/open-cidr", "Terraform references world-open CIDR", "MEDIUM", "LOW", "Infrastructure", rel, line_no, "0.0.0.0/0", "A network rule may expose a service publicly.", "Review the complete resource and restrict ingress to intended ranges.", "Inspect the planned security group or firewall rules.", cwe="CWE-284", exploitability="THEORETICAL"))
    return result


LOCKS = {"package.json": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"), "Gemfile": ("Gemfile.lock",), "composer.json": ("composer.lock",)}


def scan_hygiene(paths: set[str]) -> tuple[list[Finding], list[Check]]:
    result = []
    for manifest, locks in LOCKS.items():
        if manifest in paths and not any(lock in paths for lock in locks):
            result.append(make("hygiene/missing-lock/" + manifest, "Dependency lockfile missing", "LOW", "HIGH", "Dependencies", manifest, 1, "Manifest present without matching lockfile", "Dependency resolution can drift between runs.", "Commit a lockfile if this is a deployable application.", "Confirm repeat installs resolve the same versions.", cwe="CWE-1104"))
    checks = [Check("Repository hygiene", "CHECKED", "rivet")]
    return result, checks


def run_builtin(texts: dict[str, str]) -> tuple[list[Finding], list[Check]]:
    findings = []
    for rel, text in texts.items():
        findings.extend(scan_secrets(rel, text))
        suffix = Path(rel).suffix.lower()
        if suffix == ".py":
            findings.extend(scan_python(rel, text))
            findings.extend(scan_python_auth(rel, text))
            findings.extend(scan_python_ai(rel, text))
        elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
            findings.extend(scan_js(rel, text))
        findings.extend(scan_config(rel, text))
        findings.extend(scan_mcp_config(rel, text))
    hygiene, checks = scan_hygiene(set(texts))
    findings.extend(hygiene)
    cross_file, truncated = scan_python_project(texts)
    findings.extend(cross_file)
    checks.append(Check("Python inter-file data flow", "PARTIAL" if truncated else "CHECKED", "W.Audit bounded local-import flow", "Local imports, helper arguments and returns; limits: 100 files, depth 5, 10000 nodes, 0.25 seconds"))
    checks += [Check("Secrets", "CHECKED", "rivet patterns", "Current text files only"), Check("Source SAST", "CHECKED", "rivet AST/patterns", "Selected Python and JS/TS rules"), Check("Infrastructure and CI", "CHECKED", "rivet patterns", "Selected Docker, Compose, Terraform and GitHub Actions rules")]
    return findings, checks
