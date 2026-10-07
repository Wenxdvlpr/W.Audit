import json
from pathlib import Path
import unittest

from rivet.mcp import scan_mcp_config


class McpTests(unittest.TestCase):
    def test_broad_mcp_config_candidates(self):
        path = Path(__file__).parent / "fixtures/mcp-insecure/.cursor/mcp.json"
        findings = scan_mcp_config(".cursor/mcp.json", path.read_text())
        self.assertEqual({"mcp/shell-command", "mcp/broad-filesystem", "mcp/plain-http"}, {x.rule for x in findings})
        self.assertTrue(all(x.status == "NEEDS_MANUAL_REVIEW" for x in findings))

    def test_narrow_local_config_is_clean(self):
        data = {"mcpServers": {"local": {"command": "python", "args": ["server.py"], "url": "http://localhost:9000/mcp"}}}
        self.assertEqual([], scan_mcp_config("mcp.json", json.dumps(data)))


if __name__ == "__main__":
    unittest.main()
