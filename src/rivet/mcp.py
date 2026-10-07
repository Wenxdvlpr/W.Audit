"""Conservative, static MCP configuration checks."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from .model import Finding


MCP_FILENAMES = {"mcp.json", "claude_desktop_config.json", "mcp_config.json"}


def make(rule, title, severity, confidence, category, path, line, evidence, impact, fix, verify, scanner="Rivet MCP", cwe="", exploitability="CONDITIONAL") -> Finding:
    return Finding(rule, title, severity, confidence, category, path, line, evidence, impact, fix, verify, scanner, cwe, exploitability, "NEEDS_MANUAL_REVIEW")


def scan_mcp_config(rel: str, text: str) -> list[Finding]:
    if Path(rel).name.lower() not in MCP_FILENAMES or len(text) > 2_000_000:
        return []
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    if not isinstance(data, dict) or not isinstance(data.get("mcpServers"), dict):
        return []
    findings = []
    for name, server in list(data["mcpServers"].items())[:500]:
        if not isinstance(name, str) or not isinstance(server, dict):
            continue
        command = str(server.get("command", "")).lower()
        args = server.get("args", [])
        args = args if isinstance(args, list) else []
        if Path(command).name in {"sh", "bash", "zsh", "powershell", "pwsh", "cmd", "cmd.exe"} and any(str(arg).lower() in {"-c", "-command", "/c"} for arg in args):
            findings.append(make("mcp/shell-command", "MCP server starts through a command shell", "MEDIUM", "HIGH", "AI/LLM", rel, 1, f"MCP server {name} uses a shell command", "A broad MCP command surface may let agent actions execute unexpected commands.", "Use a fixed executable and constrain tool arguments and approvals.", "Review the server command and test rejected tool inputs.", scanner="Rivet MCP", cwe="CWE-78", exploitability="CONDITIONAL"))
        if "filesystem" in " ".join(str(arg).lower() for arg in args[:10]) and any(str(arg) in {"/", "~", ".."} for arg in args):
            findings.append(make("mcp/broad-filesystem", "MCP filesystem server has a broad root", "MEDIUM", "MEDIUM", "AI/LLM", rel, 1, f"MCP server {name} permits a broad filesystem root", "An agent with this tool may access more files than its task requires.", "Restrict filesystem roots to specific project directories.", "Confirm the server denies paths outside the approved directory.", scanner="Rivet MCP", cwe="CWE-732", exploitability="CONDITIONAL"))
        url = server.get("url")
        if isinstance(url, str) and url.startswith("http://"):
            try:
                host = urlsplit(url).hostname
            except ValueError:
                host = None
            if host not in {"localhost", "127.0.0.1", "::1"}:
                findings.append(make("mcp/plain-http", "Remote MCP server uses unencrypted HTTP", "LOW", "HIGH", "AI/LLM", rel, 1, f"MCP server {name} uses HTTP", "Tool requests may be exposed or modified in transit.", "Use HTTPS with server authentication.", "Inspect the configured transport and verify TLS.", scanner="Rivet MCP", cwe="CWE-319", exploitability="CONDITIONAL"))
    return findings
