import unittest
from pathlib import Path

from rivet.ai import scan_python_ai
from rivet.discovery import discover


class AiTests(unittest.TestCase):
    def test_llm_output_to_shell(self):
        code = '''
import os
def agent(client):
    response = client.responses.create(model="example", input="hello")
    llm_output = response.output_text
    os.system(llm_output)
'''
        findings = scan_python_ai("agent.py", code)
        self.assertEqual(1, len(findings))
        self.assertEqual("ai/output-to-shell", findings[0].rule)
        self.assertEqual("MEDIUM", findings[0].severity)
        self.assertEqual("NEEDS_MANUAL_REVIEW", findings[0].status)

    def test_remote_model_code_and_dangerous_deserialization(self):
        code = '''
from transformers import AutoModel
from langchain_community.vectorstores import FAISS
model = AutoModel.from_pretrained("example", trust_remote_code=True)
store = FAISS.load_local("index", embeddings, allow_dangerous_deserialization=True)
'''
        self.assertEqual({"ai/trust-remote-code", "ai/dangerous-deserialization"}, {f.rule for f in scan_python_ai("ai.py", code)})

    def test_fixed_command_not_reported(self):
        code = '''
import os
def agent(response):
    llm_output = response.output_text
    os.system("echo ready")
'''
        self.assertEqual([], scan_python_ai("ai.py", code))

    def test_discovery_ai_frameworks(self):
        texts = {"pyproject.toml": 'dependencies=["openai", "anthropic", "langchain", "llama-index", "google-generativeai", "mcp"]'}
        profile = discover([(Path("pyproject.toml"), "pyproject.toml")], texts)
        self.assertTrue({"OpenAI API", "Anthropic API", "LangChain", "LlamaIndex", "Gemini", "MCP"} <= set(profile["frameworks"]))


if __name__ == "__main__":
    unittest.main()
