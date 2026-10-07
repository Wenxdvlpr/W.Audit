from __future__ import annotations

from pathlib import Path

LANGUAGES = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust", ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".php": "PHP", ".rb": "Ruby", ".swift": "Swift", ".dart": "Dart", ".c": "C", ".cpp": "C++", ".sol": "Solidity"}
MARKERS = {"FastAPI": "fastapi", "Django": "django", "Flask": "flask", "React": "react", "Next.js": "next", "Express": "express", "Vue": "vue", "Angular": "@angular/core", "Spring": "spring-boot", "Rails": "rails", "OpenAI API": "openai", "Anthropic API": "anthropic", "Gemini": "google-generativeai", "LangChain": "langchain", "LlamaIndex": "llama-index", "MCP": "mcp"}


def discover(files: list[tuple[Path, str]], texts: dict[str, str]) -> dict:
    paths = {rel for _, rel in files}
    langs = sorted({LANGUAGES[Path(rel).suffix.lower()] for rel in paths if Path(rel).suffix.lower() in LANGUAGES})
    manifests = "\n".join(texts.get(p, "")[:200_000].lower() for p in paths if Path(p).name in {"pyproject.toml", "requirements.txt", "package.json", "Cargo.toml", "go.mod", "pom.xml", "Gemfile", "composer.json"})
    frameworks = sorted(name for name, marker in MARKERS.items() if marker in manifests)
    if any(Path(path).name.lower() in {"mcp.json", "claude_desktop_config.json", "mcp_config.json"} for path in paths) and "MCP" not in frameworks:
        frameworks.append("MCP")
    infra = sorted({kind for kind, pred in {
        "Docker": lambda p: Path(p).name.startswith("Dockerfile") or Path(p).name in {"compose.yaml", "docker-compose.yml"},
        "Kubernetes": lambda p: "/k8s/" in f"/{p}" or "/kubernetes/" in f"/{p}",
        "Terraform": lambda p: p.endswith(".tf"),
        "GitHub Actions": lambda p: p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml")),
    }.items() if any(pred(p) for p in paths)})
    databases = sorted(name for name in ("postgres", "mysql", "sqlite", "mongodb", "redis", "supabase", "firebase") if name in manifests)
    areas = []
    corpus = "\n".join(v[:100_000].lower() for k, v in texts.items() if Path(k).suffix in {".py", ".js", ".ts", ".tsx"})[:2_000_000]
    for area, words in {"Authentication": ("login", "password", "jwt"), "File uploads": ("upload", "multipart"), "AI tool calling": ("tool_call", "function_call"), "Database writes": ("insert", "update", "execute(")}.items():
        if any(w in corpus for w in words):
            areas.append(area)
    return {"languages": langs, "frameworks": frameworks, "infrastructure": infra, "databases": databases, "security_areas": areas}
