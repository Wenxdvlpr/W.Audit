import base64
import json
from pathlib import Path
import tempfile
import unittest

from rivet.cli import main
from rivet.sbom import generate


class SbomTests(unittest.TestCase):
    def test_pinned_python_and_npm_lock_graph(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "requirements.txt").write_text("requests==2.32.3\n")
            integrity = "sha256-" + base64.b64encode(bytes(range(32))).decode()
            lock = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"foo": "1.0.0"}}, "node_modules/foo": {"version": "1.0.0", "integrity": integrity, "dependencies": {"bar": "2.0.0"}}, "node_modules/bar": {"version": "2.0.0"}}}
            (root / "package-lock.json").write_text(json.dumps(lock))
            bom = generate(root)
            self.assertEqual("CycloneDX", bom["bomFormat"])
            self.assertEqual(3, len(bom["components"]))
            edges = {x["ref"]: x["dependsOn"] for x in bom["dependencies"]}
            self.assertIn("pkg:npm/foo@1.0.0", edges["rivet:project"])
            self.assertIn("pkg:pypi/requests@2.32.3", edges["rivet:project"])
            self.assertEqual(["pkg:npm/bar@2.0.0"], edges["pkg:npm/foo@1.0.0"])
            foo = next(x for x in bom["components"] if x["name"] == "foo")
            self.assertEqual(bytes(range(32)).hex(), foo["hashes"][0]["content"])
            self.assertTrue(all(x["purl"] == x["bom-ref"] for x in bom["components"]))
            properties = {x["name"]: x["value"] for x in foo["properties"]}
            self.assertEqual("DIRECT", properties["rivet:dependency-type"].upper())
            self.assertEqual("RUNTIME", properties["rivet:environment"])
            python_component = next(x for x in bom["components"] if x["name"] == "requests")
            self.assertEqual("RUNTIME", {x["name"]: x["value"] for x in python_component["properties"]}["rivet:environment"])
            output = root / "bom.json"
            self.assertEqual(0, main(["sbom", str(root), "--offline", "--output", str(output)]))
            self.assertTrue(output.exists())

    def test_release_fixtures_cover_python_and_npm_lock_versions(self):
        fixtures = Path(__file__).parent / "fixtures"
        for name, expected in (("sca-python-vulnerable", "pkg:pypi/requests@2.19.0"), ("sca-python-clean", "pkg:pypi/packaging@25.0"), ("sca-python-dev", "pkg:pypi/pytest@8.3.4"), ("sca-npm-vulnerable", "pkg:npm/lodash@4.17.20"), ("sca-npm-clean", None)):
            bom = generate(fixtures / name)
            if expected is None:
                self.assertEqual([], bom["components"], "the deterministic root-only clean npm fixture has no third-party packages")
            else:
                self.assertIn(expected, {item["purl"] for item in bom["components"]})
            self.assertEqual("CycloneDX", bom["bomFormat"])
            self.assertEqual("1.6", bom["specVersion"])
            self.assertIn("rivet:project", {item["ref"] for item in bom["dependencies"]})
            if name == "sca-python-dev":
                component = bom["components"][0]
                self.assertEqual("DEV", {x["name"]: x["value"] for x in component["properties"]}["rivet:environment"])

    def test_symlinked_manifest_outside_root_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "root"
            root.mkdir()
            (base / "requirements.txt").write_text("outside==1.0\n")
            (root / "requirements.txt").symlink_to(base / "requirements.txt")
            self.assertEqual([], generate(root)["components"])


if __name__ == "__main__":
    unittest.main()
