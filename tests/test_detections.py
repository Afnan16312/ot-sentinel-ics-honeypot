from __future__ import annotations

import unittest
from pathlib import Path

from scripts.validate_detections import (
    ROOT,
    SigmaRule,
    load_suricata_rules,
    sigma_matches,
    suricata_matches,
    validate_pack,
)


class DetectionPackTests(unittest.TestCase):
    def test_complete_pack_matches_all_declared_fixtures(self):
        summary, errors = validate_pack(ROOT)

        self.assertEqual(errors, [])
        self.assertEqual(summary["sigma_rules"], 4)
        self.assertEqual(summary["wazuh_alert_rules"], 4)
        self.assertEqual(summary["suricata_rules"], 4)
        self.assertGreaterEqual(summary["negative_cases"], 2)

    def test_sigma_exists_modifier_requires_real_evidence(self):
        rule = SigmaRule(
            name="evidence",
            rule_id="00000000-0000-0000-0000-000000000000",
            selection={"event_type": "known_exploit_probe", "decoded.signature|exists": True},
        )

        self.assertFalse(
            sigma_matches(rule, {"event_type": "known_exploit_probe", "decoded": {}})
        )
        self.assertTrue(
            sigma_matches(
                rule,
                {
                    "event_type": "known_exploit_probe",
                    "decoded": {"signature": "fixture-signature"},
                },
            )
        )

    def test_suricata_rules_use_native_modbus_semantics(self):
        path = Path(ROOT, "detections", "suricata", "ot_sentinel_modbus.rules")
        rules, errors = load_suricata_rules(path)
        broadcast_write = {
            "protocol": "modbus",
            "modbus": {
                "unit": 0,
                "function": 16,
                "function_class": "assigned",
                "access": "write",
            },
        }

        self.assertEqual(errors, [])
        self.assertEqual(
            {rule.sid for rule in rules if suricata_matches(rule, broadcast_write)},
            {4200501, 4200502},
        )


if __name__ == "__main__":
    unittest.main()
