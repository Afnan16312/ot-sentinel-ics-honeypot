import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from ot_sentinel.mapper import map_event
from ot_sentinel.model import Event
from ot_sentinel.operations import AlertPolicy, HealthTracker, WebhookAlerter, load_alert_settings


def control_event(session_id: str = "session-1") -> Event:
    decoded = {"operation": "write_single", "function_code": 6}
    event = Event(
        protocol="modbus",
        source_ip="198.51.100.10",
        source_port=40000,
        destination_port=502,
        event_type="protocol_request",
        session_id=session_id,
        decoded=decoded,
        severity="high",
        raw_payload_hex="deadbeef",
    )
    event.techniques = map_event(event.protocol, event.event_type, decoded)
    return event


class RecordingAlerter(WebhookAlerter):
    def __init__(self, health: HealthTracker) -> None:
        super().__init__("http://127.0.0.1:9999/alert", "0123456789abcdef", health)
        self.sent: list[dict] = []

    def _post(self, payload: dict) -> None:
        self.sent.append(payload)


class OperationsTests(unittest.IsolatedAsyncioTestCase):
    async def test_alert_is_redacted_and_deduplicated(self):
        health = HealthTracker("test-sensor")
        alerter = RecordingAlerter(health)
        await alerter.start()
        event = control_event()
        self.assertTrue(await alerter.submit(event))
        self.assertFalse(await alerter.submit(event))
        await asyncio.wait_for(alerter.queue.join(), timeout=2)
        await alerter.close()
        self.assertEqual(len(alerter.sent), 1)
        encoded = json.dumps(alerter.sent[0])
        self.assertNotIn("198.51.100.10", encoded)
        self.assertNotIn("deadbeef", encoded)
        self.assertEqual(alerter.sent[0]["protocol"], "modbus")
        self.assertEqual(alerter.sent[0]["mitre_attack_ids"], ["T1692.001", "T0836"])
        self.assertRegex(alerter.sent[0]["source_hash"], r"^[a-f0-9]{24}$")
        self.assertNotIn("event_id", alerter.sent[0])

    async def test_low_signal_event_does_not_alert(self):
        health = HealthTracker("test-sensor")
        alerter = RecordingAlerter(health)
        event = Event("modbus", "192.0.2.1", 1234, 502, "connection")
        self.assertFalse(AlertPolicy().should_alert(event))
        self.assertFalse(await alerter.submit(event))

    async def test_health_snapshot_is_atomic_and_contains_counts(self):
        health = HealthTracker("test-sensor")
        health.record(control_event())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "health.json"
            health.write(path, queue_depth=2, collector_queue_depth=3)
            snapshot = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(snapshot["status"], "ok")
        self.assertEqual(snapshot["total_events"], 1)
        self.assertEqual(snapshot["alert_queue_depth"], 2)
        self.assertEqual(snapshot["collector_queue_depth"], 3)
        self.assertIsNone(snapshot["max_concurrent_sessions"])
        self.assertEqual(snapshot["active_sessions"], 0)
        self.assertEqual(snapshot["rejected_sessions"], 0)

    def test_alert_settings_are_dependency_free_and_safe_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.yaml"
            path.write_text(
                '{"enabled": true, "webhook_url": "https://alerts.example/ot", '
                '"secret_env": "OT_ALERT_SECRET", "queue_size": 5, "timeout_seconds": 3}',
                encoding="utf-8",
            )
            settings = load_alert_settings(path)
        self.assertTrue(settings.enabled)
        self.assertEqual(settings.queue_size, 5)
        self.assertEqual(settings.secret_env, "OT_ALERT_SECRET")


if __name__ == "__main__":
    unittest.main()
