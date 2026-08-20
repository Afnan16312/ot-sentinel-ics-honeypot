import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "infra" / "oracle"


class OracleDeploymentTests(unittest.TestCase):
    def test_compose_override_keeps_internal_and_edge_networks(self):
        text = (ORACLE / "docker-compose.oracle.yml").read_text(encoding="utf-8")
        self.assertIn('restart: "no"', text)
        self.assertIn("- sensor_net", text)
        self.assertIn("- sensor_edge", text)
        self.assertIn("external: true", text)
        self.assertIn("name: ot-sentinel-edge", text)

    def test_firewall_helper_creates_edge_and_blocks_new_egress(self):
        text = (ORACLE / "ot-sentinel-firewall").read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", text)
        self.assertIn("172.31.250.0/29", text)
        self.assertIn("ACTUAL_DRIVER", text)
        self.assertIn("ACTUAL_SUBNET", text)
        self.assertIn("DOCKER-USER", text)
        self.assertIn("RELATED,ESTABLISHED", text)
        self.assertIn('--ctstate NEW -j DROP', text)
        self.assertIn("refusing to start", text)

    def test_systemd_restores_firewall_before_compose(self):
        text = (ORACLE / "ot-sentinel.service").read_text(encoding="utf-8")
        self.assertIn("Requires=docker.service", text)
        self.assertIn("RemainAfterExit=yes", text)
        self.assertIn("ExecStartPre=/usr/local/sbin/ot-sentinel-firewall", text)
        self.assertIn("infra/oracle/docker-compose.oracle.yml up -d", text)
        self.assertIn("infra/oracle/docker-compose.oracle.yml stop", text)

    def test_logrotate_policy_is_bounded(self):
        text = (ORACLE / "logrotate.ot-sentinel").read_text(encoding="utf-8")
        self.assertIn("daily", text)
        self.assertIn("rotate 35", text)
        self.assertIn("maxsize 50M", text)
        self.assertIn("compress", text)
        self.assertIn("copytruncate", text)

    def test_public_deployment_material_excludes_known_private_identifiers(self):
        paths = [
            *ORACLE.iterdir(),
            ROOT / "docs" / "ORACLE_CLOUD_RUNBOOK.md",
            ROOT / "docs" / "LIVE_DEPLOYMENT_RECORD.md",
        ]
        combined = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in paths
            if path.is_file()
        )
        self.assertNotIn("ocid1.", combined.lower())
        self.assertNotIn("private key-----", combined.lower())
        documented_addresses = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", combined))
        self.assertLessEqual(
            documented_addresses,
            {"0.0.0.0", "1.1.1.1", "127.0.0.1", "172.31.250.0"},
        )


if __name__ == "__main__":
    unittest.main()
