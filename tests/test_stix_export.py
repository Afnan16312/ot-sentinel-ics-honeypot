import base64
import json
import unittest
from uuid import UUID

import stix2validator

from ot_sentinel.stix_export import export_events


def sample_event(*, is_demo=True, sanitized=False):
    event = {
        "event_id": "event-001",
        "session_id": "session-001",
        "sensor_id": "lab-sensor",
        "observed_at": "2026-08-17T10:30:00+00:00",
        "protocol": "modbus",
        "source_port": 41000,
        "destination_port": 502,
        "event_type": "protocol_request",
        "byte_count": 12,
        "decoded": {
            "operation": "write_single",
            "function_code": 6,
            "address": 12,
            "payload": "do-not-publish",
            "peer": "203.0.113.8",
        },
        "techniques": [
            {
                "technique_id": "T1692.001",
                "name": "Unauthorized Message: Command Message",
                "tactic": "Impair Process Control",
                "confidence": "high",
                "rationale": "A control command attempted to change decoy state.",
            }
        ],
        "severity": "high",
        "is_demo": is_demo,
        "tags": ["synthetic"] if is_demo else ["honeypot"],
    }
    if sanitized:
        event.update({"source_id": "src-safe-example", "sanitized": True})
    else:
        event.update({"source_ip": "203.0.113.8", "raw_payload_hex": "deadbeef"})
    return event


class StixExportTests(unittest.TestCase):
    def test_public_profile_is_deterministic_and_contains_no_raw_evidence(self):
        first = export_events([sample_event()], profile="public", salt="unit-test-salt")
        second = export_events([sample_event()], profile="public", salt="unit-test-salt")
        self.assertEqual(first, second)

        serialized = json.dumps(first)
        self.assertNotIn("203.0.113.8", serialized)
        self.assertNotIn("deadbeef", serialized)
        self.assertNotIn("do-not-publish", serialized)
        self.assertNotIn("payload_bin", serialized)
        self.assertIn("src-", serialized)

        observed = next(item for item in first["objects"] if item["type"] == "observed-data")
        self.assertEqual(observed["x_ot_sentinel_data_classification"], "synthetic")
        self.assertEqual(observed["x_ot_sentinel_decoded"]["function_code"], 6)
        self.assertNotIn("payload", observed["x_ot_sentinel_decoded"])
        self.assertNotIn("peer", observed["x_ot_sentinel_decoded"])
        relationship = next(item for item in first["objects"] if item["type"] == "relationship")
        self.assertEqual(
            relationship["description"],
            "Mapped from allow-listed OT protocol evidence by OT Sentinel.",
        )

    def test_public_profile_accepts_already_sanitized_input_without_salt(self):
        bundle = export_events([sample_event(sanitized=True)], profile="public")
        serialized = json.dumps(bundle)
        self.assertIn("src-safe-example", serialized)
        self.assertNotIn("ipv4-addr", serialized)
        source = next(item for item in bundle["objects"] if item["type"] == "domain-name")
        traffic = next(item for item in bundle["objects"] if item["type"] == "network-traffic")
        self.assertTrue(source["value"].endswith(".invalid"))
        self.assertEqual(traffic["src_ref"], source["id"])

    def test_public_profile_requires_salt_for_raw_source(self):
        with self.assertRaisesRegex(ValueError, "salt is required"):
            export_events([sample_event()], profile="public")

    def test_public_profile_rejects_an_unsafe_existing_pseudonym(self):
        event = sample_event(sanitized=True)
        event["source_ip"] = "203.0.113.8"
        event["source_id"] = "src-203.0.113.8"
        with self.assertRaisesRegex(AssertionError, "raw source IP"):
            export_events([event], profile="public")

    def test_private_profile_preserves_source_and_payload_as_standard_scos(self):
        bundle = export_events([sample_event(is_demo=False)], profile="private")
        ipv4 = next(item for item in bundle["objects"] if item["type"] == "ipv4-addr")
        artifact = next(item for item in bundle["objects"] if item["type"] == "artifact")
        observed = next(item for item in bundle["objects"] if item["type"] == "observed-data")

        self.assertEqual(ipv4["value"], "203.0.113.8")
        self.assertEqual(base64.b64decode(artifact["payload_bin"]), bytes.fromhex("deadbeef"))
        self.assertEqual(observed["x_ot_sentinel_data_classification"], "live")
        self.assertIn(ipv4["id"], observed["object_refs"])
        self.assertIn(artifact["id"], observed["object_refs"])
        traffic = next(item for item in bundle["objects"] if item["type"] == "network-traffic")
        self.assertEqual(traffic["src_payload_ref"], artifact["id"])

    def test_attack_mapping_has_external_reference_confidence_and_provenance(self):
        bundle = export_events([sample_event(sanitized=True)], profile="public")
        pattern = next(item for item in bundle["objects"] if item["type"] == "attack-pattern")
        relationship = next(item for item in bundle["objects"] if item["type"] == "relationship")

        reference = pattern["external_references"][0]
        self.assertEqual(reference["source_name"], "mitre-attack-ics")
        self.assertEqual(reference["external_id"], "T1692.001")
        self.assertEqual(reference["url"], "https://attack.mitre.org/techniques/T1692/001/")
        self.assertEqual(relationship["confidence"], 75)
        self.assertEqual(relationship["x_ot_sentinel_mapping_status"], "evidence-based-hypothesis")

    def test_bundle_and_object_identifiers_have_stix_shapes(self):
        bundle = export_events([sample_event(sanitized=True)], profile="public")
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        for item in bundle["objects"]:
            object_type, value = item["id"].split("--", maxsplit=1)
            self.assertEqual(object_type, item["type"])
            UUID(value)
            self.assertEqual(item.get("spec_version"), "2.1")

    def test_public_and_private_bundles_pass_the_stix_21_validator(self):
        options = stix2validator.ValidationOptions(version="2.1", silent=True)
        public = export_events([sample_event(sanitized=True)], profile="public")
        private = export_events([sample_event(is_demo=False)], profile="private")
        for profile, bundle in (("public", public), ("private", private)):
            with self.subTest(profile=profile):
                result = stix2validator.validate_string(json.dumps(bundle), options)
                self.assertTrue(result.is_valid, [str(error) for error in result.errors])

    def test_empty_and_unknown_profile_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "At least one event"):
            export_events([], profile="public")
        with self.assertRaisesRegex(ValueError, "profile must be"):
            export_events([sample_event()], profile="partner")


if __name__ == "__main__":
    unittest.main()
