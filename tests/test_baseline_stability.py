import unittest

from rivet.checks import scan_python
from rivet.model import deduplicate, stabilize_fingerprints


class BaselineStabilityTests(unittest.TestCase):
    def test_line_movement_and_whitespace_keep_fingerprint(self):
        first = "import os\nos.system('echo test')\n"
        second = "# added header\nimport os\nos.system( 'echo test' )\n"
        a = deduplicate(scan_python("app.py", first))
        b = deduplicate(scan_python("app.py", second))
        stabilize_fingerprints(a, {"app.py": first})
        stabilize_fingerprints(b, {"app.py": second})
        self.assertEqual(a[0].fingerprint, b[0].fingerprint)


if __name__ == "__main__":
    unittest.main()
