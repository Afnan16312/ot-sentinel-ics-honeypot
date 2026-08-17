import unittest

from scripts.build_release_evidence import ROOT, evidence_files
from scripts.generate_sbom import build_sbom, dependency_names


class SupplyChainTests(unittest.TestCase):
    def test_sbom_is_spdx_23_and_lists_declared_dependencies(self):
        sbom = build_sbom()
        self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
        self.assertEqual(sbom["dataLicense"], "CC0-1.0")
        package_names = {package["name"].lower() for package in sbom["packages"]}
        self.assertIn("ot-sentinel", package_names)
        self.assertTrue({name.lower() for name in dependency_names()}.issubset(package_names))

    def test_release_evidence_scope_excludes_private_runtime_data(self):
        relative = {path.relative_to(ROOT).as_posix() for path in evidence_files()}
        self.assertIn("src/ot_sentinel/sensor.py", relative)
        self.assertIn("docs/THREAT_MODEL.md", relative)
        self.assertFalse(any(path.startswith("logs/") for path in relative))
        self.assertFalse(any(path.startswith("data/private/") for path in relative))
        self.assertFalse(any(path == ".env" for path in relative))


if __name__ == "__main__":
    unittest.main()
