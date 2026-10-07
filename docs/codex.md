# Codex use

Codex reads repository `AGENTS.md` instructions. Copy the short [AGENTS.md](../AGENTS.md) into the target repository or ask Codex to follow [AGENT_SECURITY_GUIDE.md](../AGENT_SECURITY_GUIDE.md) explicitly. Install W.Audit in a trusted environment, then request: “Run W.Audit on this repository offline, inspect the report, validate HIGH findings, and explain the top fixes. Do not change code yet.” The compatibility CLI command is `rivet`; the CLI is useful without an AI layer.

Codex instruction discovery is described in the [official OpenAI Codex prompting guide](https://developers.openai.com/cookbook/examples/gpt-5/codex_prompting_guide).
