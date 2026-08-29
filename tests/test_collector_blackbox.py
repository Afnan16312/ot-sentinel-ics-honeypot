import http.client
import json
import socket
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from ot_sentinel.collector import (
    CollectorHTTPServer,
    CollectorStore,
    CollectorVerifier,
    make_handler,
)
from ot_sentinel.transport import canonical_signature

SENSOR_ID = "synthetic-sensor-01"
SENSOR_SECRET = "collector-test-secret-not-production"


class FailingOnceStore:
    def __init__(self) -> None:
        self.failed = False
        self.events: list[dict] = []
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        with self._lock:
            if not self.failed:
                self.failed = True
                raise OSError("synthetic private path marker must not escape")
            self.events.append(event)


class GatedStore:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.events: list[dict] = []

    def append(self, event: dict) -> None:
        self.entered.set()
        if not self.release.wait(timeout=2):
            raise OSError("synthetic gated store timed out")
        self.events.append(event)


class CollectorBlackBoxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name) / "collector.jsonl"
        self.server, self.thread = self._start_server(CollectorStore(self.output))

    def tearDown(self) -> None:
        self._stop_server(self.server, self.thread)
        self.temporary.cleanup()

    def _start_server(self, store, *, request_timeout: float = 0.2):
        verifier = CollectorVerifier({SENSOR_ID: SENSOR_SECRET})
        server = CollectorHTTPServer(
            ("127.0.0.1", 0),
            make_handler(verifier, store, request_timeout=request_timeout),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def _stop_server(self, server, thread) -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    @contextmanager
    def _alternate_server(self, store, *, request_timeout: float = 0.2):
        server, thread = self._start_server(store, request_timeout=request_timeout)
        try:
            yield server
        finally:
            self._stop_server(server, thread)

    def _envelope(
        self,
        *,
        event_id: str | None = None,
        envelope_sensor: str = SENSOR_ID,
        event_sensor: str = SENSOR_ID,
        marker: str | None = None,
    ) -> bytes:
        event = {
            "event_id": event_id or str(uuid.uuid4()),
            "session_id": "synthetic-session",
            "sensor_id": event_sensor,
            "observed_at": "2026-01-01T00:00:00+00:00",
            "protocol": "modbus",
            "event_type": "connection",
        }
        if marker:
            event["synthetic_note"] = marker
        envelope = {
            "schema": "ot-sentinel-envelope/1",
            "sensor_id": envelope_sensor,
            "sent_at": "2026-01-01T00:00:00+00:00",
            "event": event,
        }
        return json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()

    def _headers(
        self,
        body: bytes,
        *,
        sensor_id: str = SENSOR_ID,
        secret: str = SENSOR_SECRET,
        timestamp: int | None = None,
        content_type: str = "application/json",
    ) -> dict[str, str]:
        value = str(int(time.time()) if timestamp is None else timestamp)
        signature = canonical_signature(secret.encode(), value, body)
        return {
            "Content-Type": content_type,
            "X-OT-Sensor": sensor_id,
            "X-OT-Timestamp": value,
            "X-OT-Signature": f"sha256={signature}",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        server=None,
    ) -> tuple[int, dict[str, str], dict]:
        active_server = server or self.server
        connection = http.client.HTTPConnection(
            "127.0.0.1", active_server.server_address[1], timeout=2
        )
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = json.loads(response.read())
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
        connection.close()
        return status, response_headers, payload

    def _raw_request(
        self,
        request: bytes,
        *,
        server=None,
        shutdown_write: bool = True,
    ) -> tuple[int, bytes]:
        active_server = server or self.server
        with socket.create_connection(active_server.server_address, timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(request)
            if shutdown_write:
                connection.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        response = b"".join(chunks)
        status = int(response.split(b" ", 2)[1])
        return status, response.split(b"\r\n\r\n", 1)[-1]

    def test_health_contract_remains_compatible(self):
        status, headers, payload = self._request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["cache-control"], "no-store")

    def test_valid_signed_event_is_accepted_and_stored(self):
        body = self._envelope()
        status, headers, payload = self._request(
            "POST", "/v1/events", body=body, headers=self._headers(body)
        )
        self.assertEqual(status, 202)
        self.assertTrue(payload["accepted"])
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        stored = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertTrue(stored["transport_authenticated"])
        self.assertEqual(stored["event_id"], payload["event_id"])

    def test_invalid_hmac_is_rejected(self):
        body = self._envelope()
        headers = self._headers(body)
        headers["X-OT-Signature"] = "sha256=" + ("0" * 64)
        status, _, payload = self._request(
            "POST", "/v1/events", body=body, headers=headers
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "authentication failed")

    def test_unknown_sensor_is_rejected_without_enumeration(self):
        body = self._envelope(envelope_sensor="synthetic-unknown", event_sensor="synthetic-unknown")
        headers = self._headers(
            body,
            sensor_id="synthetic-unknown",
            secret="unknown-test-secret-not-production",
        )
        status, _, payload = self._request(
            "POST", "/v1/events", body=body, headers=headers
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "authentication failed")
        self.assertNotIn("synthetic-unknown", json.dumps(payload))

    def test_sensor_identity_mismatch_is_rejected(self):
        for envelope_sensor, event_sensor in [
            ("synthetic-other", SENSOR_ID),
            (SENSOR_ID, "synthetic-other"),
        ]:
            with self.subTest(envelope_sensor=envelope_sensor, event_sensor=event_sensor):
                body = self._envelope(
                    envelope_sensor=envelope_sensor,
                    event_sensor=event_sensor,
                )
                status, _, payload = self._request(
                    "POST", "/v1/events", body=body, headers=self._headers(body)
                )
                self.assertEqual(status, 401)
                self.assertEqual(payload["error"], "authentication failed")

    def test_missing_authentication_headers_are_rejected(self):
        body = self._envelope()
        status, _, payload = self._request(
            "POST",
            "/v1/events",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "authentication failed")

    def test_expired_and_future_timestamps_are_rejected(self):
        now = int(time.time())
        for timestamp in (now - 301, now + 301):
            with self.subTest(timestamp=timestamp):
                body = self._envelope()
                status, _, payload = self._request(
                    "POST",
                    "/v1/events",
                    body=body,
                    headers=self._headers(body, timestamp=timestamp),
                )
                self.assertEqual(status, 401)
                self.assertEqual(payload["error"], "authentication failed")

    def test_replayed_event_is_rejected(self):
        body = self._envelope()
        headers = self._headers(body)
        first, _, _ = self._request("POST", "/v1/events", body=body, headers=headers)
        replay, _, payload = self._request(
            "POST", "/v1/events", body=body, headers=headers
        )
        self.assertEqual(first, 202)
        self.assertEqual(replay, 409)
        self.assertEqual(payload["error"], "duplicate event")

    def test_malformed_json_is_rejected(self):
        body = b'{"schema":"synthetic-marker"'
        status, _, payload = self._request(
            "POST", "/v1/events", body=body, headers=self._headers(body)
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid event envelope")
        self.assertNotIn("synthetic-marker", json.dumps(payload))

    def test_missing_or_non_string_contract_fields_are_rejected(self):
        envelope = json.loads(self._envelope())
        cases = []
        without_sent_at = dict(envelope)
        without_sent_at.pop("sent_at")
        cases.append(without_sent_at)
        invalid_event_id = dict(envelope)
        invalid_event_id["event"] = dict(envelope["event"], event_id=[])
        cases.append(invalid_event_id)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                body = json.dumps(candidate, separators=(",", ":"), sort_keys=True).encode()
                status, _, payload = self._request(
                    "POST", "/v1/events", body=body, headers=self._headers(body)
                )
                self.assertEqual(status, 400)
                self.assertEqual(payload["error"], "invalid event envelope")

    def test_wrong_content_type_is_rejected(self):
        body = self._envelope()
        status, _, payload = self._request(
            "POST",
            "/v1/events",
            body=body,
            headers=self._headers(body, content_type="text/plain"),
        )
        self.assertEqual(status, 415)
        self.assertIn("application/json", payload["error"])

    def test_missing_invalid_and_duplicate_content_length_are_rejected(self):
        requests = {
            411: b"POST /v1/events HTTP/1.1\r\nHost: loopback\r\n"
            b"Content-Type: application/json\r\nConnection: close\r\n\r\n",
            400: b"POST /v1/events HTTP/1.1\r\nHost: loopback\r\n"
            b"Content-Type: application/json\r\nContent-Length: invalid\r\n"
            b"Connection: close\r\n\r\n",
        }
        for expected, request in requests.items():
            with self.subTest(expected=expected):
                status, _ = self._raw_request(request)
                self.assertEqual(status, expected)

        duplicate = (
            b"POST /v1/events HTTP/1.1\r\nHost: loopback\r\n"
            b"Content-Type: application/json\r\nContent-Length: 2\r\n"
            b"Content-Length: 3\r\nConnection: close\r\n\r\n{}"
        )
        status, _ = self._raw_request(duplicate)
        self.assertEqual(status, 400)

    def test_empty_request_is_rejected(self):
        request = (
            b"POST /v1/events HTTP/1.1\r\nHost: loopback\r\n"
            b"Content-Type: application/json\r\nContent-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )
        status, body = self._raw_request(request)
        self.assertEqual(status, 400)
        self.assertIn(b"request body is required", body)

    def test_request_larger_than_64_kib_is_rejected_before_read(self):
        request = (
            b"POST /v1/events HTTP/1.1\r\nHost: loopback\r\n"
            b"Content-Type: application/json\r\nContent-Length: 65537\r\n"
            b"Connection: close\r\n\r\n"
        )
        status, body = self._raw_request(request)
        self.assertEqual(status, 413)
        self.assertIn(b"64 KiB", body)

    def test_incomplete_request_body_is_rejected(self):
        request = (
            b"POST /v1/events HTTP/1.1\r\nHost: loopback\r\n"
            b"Content-Type: application/json\r\nContent-Length: 10\r\n"
            b"Connection: close\r\n\r\n{}"
        )
        status, body = self._raw_request(request)
        self.assertEqual(status, 400)
        self.assertIn(b"incomplete request body", body)

    def test_concurrent_valid_requests_are_serialized_without_loss(self):
        requests = []
        for index in range(16):
            body = self._envelope(event_id=f"synthetic-event-{index:02d}")
            requests.append((body, self._headers(body)))

        def submit(item):
            body, headers = item
            return self._request("POST", "/v1/events", body=body, headers=headers)[0]

        with ThreadPoolExecutor(max_workers=8) as executor:
            statuses = list(executor.map(submit, requests))
        self.assertEqual(statuses, [202] * len(requests))
        self.assertEqual(len(self.output.read_text(encoding="utf-8").splitlines()), 16)

    def test_concurrent_replay_attempts_accept_exactly_once(self):
        body = self._envelope(event_id="synthetic-replay-event")
        headers = self._headers(body)

        def submit(_):
            return self._request("POST", "/v1/events", body=body, headers=headers)[0]

        with ThreadPoolExecutor(max_workers=8) as executor:
            statuses = list(executor.map(submit, range(16)))
        self.assertEqual(statuses.count(202), 1)
        self.assertEqual(statuses.count(409), 15)
        self.assertEqual(len(self.output.read_text(encoding="utf-8").splitlines()), 1)

    def test_storage_failure_is_redacted_and_allows_retry(self):
        store = FailingOnceStore()
        with self._alternate_server(store) as server:
            body = self._envelope(event_id="synthetic-storage-retry")
            headers = self._headers(body)
            first_status, _, first_payload = self._request(
                "POST", "/v1/events", body=body, headers=headers, server=server
            )
            retry_status, _, retry_payload = self._request(
                "POST", "/v1/events", body=body, headers=headers, server=server
            )
        self.assertEqual(first_status, 503)
        self.assertEqual(first_payload["error"], "storage unavailable")
        self.assertNotIn("private path marker", json.dumps(first_payload))
        self.assertEqual(retry_status, 202)
        self.assertTrue(retry_payload["accepted"])
        self.assertEqual(len(store.events), 1)

    def test_client_body_timeout_is_bounded_and_redacted(self):
        request = (
            b"POST /v1/events HTTP/1.1\r\nHost: loopback\r\n"
            b"Content-Type: application/json\r\nContent-Length: 10\r\n"
            b"Connection: close\r\n\r\n"
        )
        started = time.monotonic()
        status, body = self._raw_request(request, shutdown_write=False)
        elapsed = time.monotonic() - started
        self.assertEqual(status, 408)
        self.assertLess(elapsed, 1.5)
        self.assertIn(b"request body timed out", body)

    def test_error_responses_do_not_echo_request_or_authentication_material(self):
        marker = "SYNTHETIC-PRIVATE-MARKER-MUST-NOT-ECHO"
        body = self._envelope(
            envelope_sensor="synthetic-unknown",
            event_sensor="synthetic-unknown",
            marker=marker,
        )
        headers = self._headers(
            body,
            sensor_id="synthetic-unknown",
            secret="unknown-test-secret-not-production",
        )
        status, response_headers, payload = self._request(
            "POST", "/v1/events", body=body, headers=headers
        )
        encoded = json.dumps(payload)
        self.assertEqual(status, 401)
        self.assertNotIn(marker, encoded)
        self.assertNotIn(headers["X-OT-Signature"], encoded)
        self.assertNotIn("synthetic-unknown", encoded)
        self.assertNotIn("traceback", encoded.lower())
        self.assertEqual(response_headers["cache-control"], "no-store")

    def test_unsupported_method_uses_privacy_safe_json_error(self):
        marker = b"SYNTHETIC-METHOD-BODY-MUST-NOT-ECHO"
        status, response_headers, payload = self._request(
            "PUT",
            "/v1/events",
            body=marker,
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(status, 501)
        self.assertEqual(payload, {"accepted": False, "error": "request rejected"})
        self.assertNotIn(marker.decode(), json.dumps(payload))
        self.assertEqual(response_headers["content-type"], "application/json")
        self.assertEqual(response_headers["server"], "OTSentinelCollector")

    def test_server_shutdown_is_graceful(self):
        store = GatedStore()
        server, server_thread = self._start_server(store)
        body = self._envelope(event_id="synthetic-in-flight-shutdown")
        headers = self._headers(body)
        result: list[int] = []

        request_thread = threading.Thread(
            target=lambda: result.append(
                self._request(
                    "POST", "/v1/events", body=body, headers=headers, server=server
                )[0]
            )
        )
        request_thread.start()
        self.assertTrue(store.entered.wait(timeout=1))

        close_thread = threading.Thread(target=lambda: self._stop_server(server, server_thread))
        close_thread.start()
        time.sleep(0.05)
        self.assertTrue(close_thread.is_alive())
        store.release.set()
        request_thread.join(timeout=2)
        close_thread.join(timeout=2)

        self.assertFalse(request_thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertEqual(result, [202])
        self.assertEqual(len(store.events), 1)


if __name__ == "__main__":
    unittest.main()
