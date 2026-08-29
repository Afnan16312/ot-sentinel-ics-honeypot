import unittest

from ot_sentinel.triage import (
    assess_event,
    factor_summary,
    next_step_for_priority,
    priority_for_score,
)


class TriageTests(unittest.TestCase):
    def test_connection_is_informational(self):
        result = assess_event({"event_type": "connection", "decoded": {}, "techniques": []})
        self.assertEqual(result.score, 0)
        self.assertEqual(result.priority, "informational")
        self.assertEqual(factor_summary(result), "No scored protocol evidence.")

    def test_control_command_is_explainable_and_high_review(self):
        result = assess_event(
            {
                "event_type": "protocol_request",
                "decoded": {"operation": "write_single"},
                "techniques": [
                    {"technique_id": "T1692.001", "confidence": "high"},
                    {"technique_id": "T0836", "confidence": "medium"},
                ],
            }
        )
        self.assertEqual(result.score, 60)
        self.assertEqual(result.priority, "high review")
        self.assertEqual([factor.code for factor in result.factors], ["control_command", "mapped_evidence"])

    def test_known_signature_uses_recorded_signature_not_event_name_alone(self):
        without_signature = assess_event(
            {"event_type": "known_exploit_probe", "decoded": {}, "techniques": []}
        )
        with_signature = assess_event(
            {
                "event_type": "known_exploit_probe",
                "decoded": {"signature": "TEST"},
                "techniques": [{"technique_id": "T0866", "confidence": "high"}],
            }
        )
        self.assertEqual(without_signature.score, 0)
        self.assertEqual(with_signature.score, 55)

    def test_modbus_read_is_scored_without_claiming_intent(self):
        result = assess_event(
            {
                "event_type": "protocol_request",
                "decoded": {"function_code": 3},
                "techniques": [{"technique_id": "T0877", "confidence": "low"}],
            }
        )
        self.assertEqual(result.score, 20)
        self.assertNotIn("intent", " ".join(f.explanation.lower() for f in result.factors))

    def test_combined_probe_and_read_preserves_both_evidence_factors(self):
        result = assess_event(
            {
                "event_type": "protocol_request",
                "decoded": {"operation": "device_probe", "function_code": 3},
                "techniques": [
                    {"technique_id": "T0846.001", "confidence": "medium"},
                    {"technique_id": "T0877", "confidence": "low"},
                ],
            }
        )
        self.assertEqual(result.score, 35)
        self.assertEqual(
            [factor.code for factor in result.factors],
            ["process_read", "protocol_probe", "mapped_evidence"],
        )

    def test_priority_boundaries_and_validation(self):
        expected = {0: "informational", 1: "routine review", 25: "elevated review", 50: "high review", 75: "urgent review", 100: "urgent review"}
        self.assertEqual({score: priority_for_score(score) for score in expected}, expected)
        with self.assertRaises(ValueError):
            priority_for_score(101)

    def test_next_step_is_bounded_to_human_review(self):
        self.assertIn("before escalation", next_step_for_priority("high review"))
        self.assertIn("no scored protocol behavior", next_step_for_priority("informational"))
        self.assertIn("before deciding", next_step_for_priority("unexpected"))


if __name__ == "__main__":
    unittest.main()
