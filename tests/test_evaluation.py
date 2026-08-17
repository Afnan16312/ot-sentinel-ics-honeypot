import unittest
from pathlib import Path

from ot_sentinel.evaluation import evaluate_mapper, load_labeled_jsonl

FIXTURE = Path(__file__).parent / "fixtures" / "evaluation" / "mapper_cases.jsonl"


class EvaluationTests(unittest.TestCase):
    def test_golden_fixture_is_reproducible(self):
        result = evaluate_mapper(load_labeled_jsonl(FIXTURE))
        self.assertEqual(result.cases, 12)
        self.assertEqual(result.exact_matches, 12)
        self.assertEqual(result.exact_match_ratio, 1.0)
        self.assertEqual(result.micro_precision, 1.0)
        self.assertEqual(result.micro_recall, 1.0)
        self.assertEqual(result.micro_f1, 1.0)
        self.assertEqual(result.macro_f1, 1.0)

    def test_false_positive_and_false_negative_are_visible(self):
        cases = [
            {
                "protocol": "modbus",
                "event_type": "protocol_request",
                "decoded": {"operation": "write_single"},
                "expected_technique_ids": ["T1692.001"],
            },
            {
                "protocol": "s7",
                "event_type": "connection",
                "decoded": {},
                "expected_technique_ids": ["T0843"],
            },
        ]
        result = evaluate_mapper(cases)
        by_id = {item.technique_id: item for item in result.techniques}
        self.assertEqual(by_id["T0836"].false_positive, 1)
        self.assertEqual(by_id["T0843"].false_negative, 1)
        self.assertEqual(result.exact_match_ratio, 0.0)

    def test_empty_case_set_is_zero_safe(self):
        result = evaluate_mapper([])
        self.assertEqual(result.cases, 0)
        self.assertEqual(result.micro_f1, 0.0)
        self.assertEqual(result.techniques, ())


if __name__ == "__main__":
    unittest.main()
