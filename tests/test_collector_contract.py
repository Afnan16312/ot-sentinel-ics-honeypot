import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "api" / "collector.openapi.json"


class CollectorContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_openapi_31_contract_has_only_the_intended_paths(self):
        self.assertEqual(self.contract["openapi"], "3.1.0")
        self.assertEqual(set(self.contract["paths"]), {"/v1/events", "/health"})
        self.assertEqual(set(self.contract["paths"]["/v1/events"]), {"post"})
        self.assertEqual(set(self.contract["paths"]["/health"]), {"get"})

    def test_event_contract_requires_all_authentication_headers(self):
        operation = self.contract["paths"]["/v1/events"]["post"]
        parameters = {item["name"]: item for item in operation["parameters"]}
        self.assertEqual(
            set(parameters),
            {"X-OT-Sensor", "X-OT-Timestamp", "X-OT-Signature", "Content-Length"},
        )
        self.assertTrue(all(item["required"] for item in parameters.values()))
        self.assertEqual(parameters["Content-Length"]["schema"]["maximum"], 65536)
        self.assertEqual(
            set(operation["security"][0]),
            {"sensorId", "requestTimestamp", "hmacSignature"},
        )

    def test_contract_documents_success_and_security_failure_responses(self):
        responses = self.contract["paths"]["/v1/events"]["post"]["responses"]
        self.assertEqual(
            set(responses),
            {"202", "400", "401", "408", "409", "411", "413", "415", "503"},
        )
        health = self.contract["paths"]["/health"]["get"]
        self.assertEqual(set(health["responses"]), {"200"})
        self.assertEqual(health["security"], [])

    def test_contract_contains_no_telemetry_or_secret_examples(self):
        encoded = json.dumps(self.contract).lower()
        for forbidden in (
            "source_ip",
            "raw_payload_hex",
            "ocid1.",
            "private key-----",
            "x-ot-signature: sha256=",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_collector_runtime_remains_framework_free(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
        collector = (ROOT / "src" / "ot_sentinel" / "collector.py").read_text(
            encoding="utf-8"
        ).lower()
        for framework in ("flask", "django", "djangorestframework"):
            self.assertNotIn(framework, project)
            self.assertNotIn(f"import {framework}", collector)
            self.assertNotIn(f"from {framework}", collector)


if __name__ == "__main__":
    unittest.main()
