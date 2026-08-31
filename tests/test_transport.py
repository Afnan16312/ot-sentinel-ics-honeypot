import json
import time
import unittest

from ot_sentinel.collector import CollectorError, CollectorVerifier
from ot_sentinel.model import Event
from ot_sentinel.operations import HealthTracker
from ot_sentinel.transport import RemoteCollectorSink


def signed_headers(sensor_id: str, secret: str, body: bytes) -> dict[str, str]:
    from ot_sentinel.transport import canonical_signature

    timestamp = str(int(time.time()))
    return {
        "X-OT-Sensor": sensor_id,
        "X-OT-Timestamp": timestamp,
        "X-OT-Signature": f"sha256={canonical_signature(secret.encode(), timestamp, body)}",
    }


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.sensor_id = "sensor-test-01"
        self.secret = "0123456789abcdef0123456789abcdef"
        self.event = Event(
            "modbus", "192.0.2.10", 40000, 502, "connection", sensor_id=self.sensor_id
        )

    def test_signed_envelope_verifies_and_replay_is_rejected(self):
        sink = RemoteCollectorSink(
            "http://127.0.0.1:9443/v1/events",
            self.sensor_id,
            self.secret,
            HealthTracker(self.sensor_id),
        )
        request = sink.build_request(self.event)
        headers = {key: value for key, value in request.header_items()}
        verifier = CollectorVerifier({self.sensor_id: self.secret})
        accepted = verifier.verify(headers, request.data)
        self.assertTrue(accepted["transport_authenticated"])
        self.assertEqual(accepted["event_id"], self.event.event_id)
        with self.assertRaisesRegex(CollectorError, "duplicate"):
            verifier.verify(headers, request.data)

    def test_transport_sends_observation_evidence_not_analytical_conclusions(self):
        self.event.severity = "high"
        request = RemoteCollectorSink(
            "http://127.0.0.1:9443/v1/events",
            self.sensor_id,
            self.secret,
            HealthTracker(self.sensor_id),
        ).build_request(self.event)
        event = json.loads(request.data)["event"]
        self.assertEqual(event["schema_version"], "ot-sentinel.observation/v1")
        self.assertNotIn("techniques", event)
        self.assertNotIn("severity", event)

    def test_tampered_body_is_rejected(self):
        sink = RemoteCollectorSink(
            "http://localhost:9443/v1/events",
            self.sensor_id,
            self.secret,
            HealthTracker(self.sensor_id),
        )
        request = sink.build_request(self.event)
        envelope = json.loads(request.data)
        envelope["event"]["protocol"] = "tampered"
        body = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
        headers = {key: value for key, value in request.header_items()}
        with self.assertRaisesRegex(CollectorError, "signature"):
            CollectorVerifier({self.sensor_id: self.secret}).verify(headers, body)

    def test_stale_timestamp_is_rejected(self):
        sink = RemoteCollectorSink(
            "http://localhost:9443/v1/events",
            self.sensor_id,
            self.secret,
            HealthTracker(self.sensor_id),
        )
        request = sink.build_request(self.event)
        headers = {key: value for key, value in request.header_items()}
        headers["X-ot-timestamp"] = str(int(time.time()) - 1000)
        with self.assertRaises(CollectorError):
            CollectorVerifier({self.sensor_id: self.secret}).verify(headers, request.data)

    def test_remote_plain_http_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            RemoteCollectorSink(
                "http://example.invalid/v1/events",
                self.sensor_id,
                self.secret,
                HealthTracker(self.sensor_id),
            )

    def test_signed_non_object_json_is_rejected_cleanly(self):
        body = b"[]"
        with self.assertRaisesRegex(CollectorError, "JSON object"):
            CollectorVerifier({self.sensor_id: self.secret}).verify(
                signed_headers(self.sensor_id, self.secret, body), body
            )


if __name__ == "__main__":
    unittest.main()
