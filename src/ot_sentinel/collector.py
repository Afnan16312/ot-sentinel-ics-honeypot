from __future__ import annotations

import argparse
import hmac
import json
import ssl
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .transport import canonical_signature


class CollectorError(ValueError):
    pass


class CollectorAuthenticationError(CollectorError):
    pass


class CollectorReplayError(CollectorError):
    pass


class CollectorPayloadError(CollectorError):
    pass


class CollectorVerifier:
    def __init__(self, sensor_secrets: Mapping[str, str], max_clock_skew: int = 300) -> None:
        if not sensor_secrets:
            raise CollectorError("at least one sensor credential is required")
        if any(len(secret) < 16 for secret in sensor_secrets.values()):
            raise CollectorError("all sensor secrets must contain at least 16 characters")
        self.sensor_secrets = {key: value.encode() for key, value in sensor_secrets.items()}
        self.max_clock_skew = min(max(max_clock_skew, 30), 900)
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def verify(self, headers: Mapping[str, str], body: bytes) -> dict:
        if len(body) > 64 * 1024:
            raise CollectorPayloadError("request exceeds 64 KiB")
        normalized_headers = {str(key).lower(): str(value) for key, value in headers.items()}
        sensor_id = normalized_headers.get("x-ot-sensor", "")
        timestamp = normalized_headers.get("x-ot-timestamp", "")
        provided = normalized_headers.get("x-ot-signature", "")
        secret = self.sensor_secrets.get(sensor_id)
        if secret is None:
            raise CollectorAuthenticationError("unknown sensor")
        try:
            numeric_timestamp = int(timestamp)
        except ValueError as exc:
            raise CollectorAuthenticationError("invalid timestamp") from exc
        if abs(time.time() - numeric_timestamp) > self.max_clock_skew:
            raise CollectorAuthenticationError("timestamp outside accepted window")
        expected = "sha256=" + canonical_signature(secret, timestamp, body)
        if not hmac.compare_digest(provided, expected):
            raise CollectorAuthenticationError("invalid signature")
        try:
            envelope = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CollectorPayloadError("invalid JSON") from exc
        if not isinstance(envelope, dict):
            raise CollectorPayloadError("envelope must be a JSON object")
        if envelope.get("schema") != "ot-sentinel-envelope/1":
            raise CollectorPayloadError("unsupported envelope schema")
        sent_at = envelope.get("sent_at")
        if not isinstance(sent_at, str) or not sent_at:
            raise CollectorPayloadError("envelope sent_at must be a non-empty string")
        if envelope.get("sensor_id") != sensor_id:
            raise CollectorAuthenticationError("sensor identity mismatch")
        event = envelope.get("event")
        if not isinstance(event, dict) or event.get("sensor_id") != sensor_id:
            raise CollectorAuthenticationError("event sensor identity mismatch")
        required = {"event_id", "session_id", "observed_at", "protocol", "event_type"}
        if not required.issubset(event):
            raise CollectorPayloadError("event is missing required fields")
        if any(not isinstance(event[field], str) or not event[field] for field in required):
            raise CollectorPayloadError("event required fields must be non-empty strings")
        replay_key = f"{sensor_id}:{event['event_id']}"
        now = time.monotonic()
        with self._lock:
            self._seen = {
                key: observed for key, observed in self._seen.items() if now - observed < 900
            }
            if replay_key in self._seen:
                raise CollectorReplayError("duplicate event")
            self._seen[replay_key] = now
        return {
            "received_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "transport_authenticated": True,
            "envelope_sent_at": sent_at,
            **event,
        }

    def release_replay(self, event: Mapping[str, object]) -> None:
        """Permit a retry when authenticated storage fails before acceptance."""
        sensor_id = str(event.get("sensor_id", ""))
        event_id = str(event.get("event_id", ""))
        if not sensor_id or not event_id:
            return
        with self._lock:
            self._seen.pop(f"{sensor_id}:{event_id}", None)


class CollectorStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


class CollectorHTTPServer(ThreadingHTTPServer):
    """Threaded server that waits for in-flight handlers during server_close()."""

    daemon_threads = False
    block_on_close = True


def make_handler(
    verifier: CollectorVerifier,
    store: CollectorStore,
    *,
    request_timeout: float = 5.0,
):
    bounded_timeout = min(max(float(request_timeout), 0.1), 15.0)

    class Handler(BaseHTTPRequestHandler):
        server_version = "OTSentinelCollector"
        sys_version = ""

        def version_string(self) -> str:
            return self.server_version

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            self._reply(code, {"accepted": False, "error": "request rejected"})

        def do_GET(self) -> None:
            if self.path != "/health":
                self._reply(404, {"error": "not found"})
                return
            self._reply(200, {"status": "ok"})

        def do_POST(self) -> None:
            if self.path != "/v1/events":
                self._reply(404, {"accepted": False, "error": "not found"})
                return
            if self.headers.get_content_type() != "application/json":
                self._error(415, "content type must be application/json")
                return

            length_values = self.headers.get_all("Content-Length", [])
            if not length_values:
                self._error(411, "content length is required")
                return
            if len(length_values) != 1:
                self._error(400, "invalid content length")
                return
            try:
                length = int(length_values[0])
            except ValueError:
                self._error(400, "invalid content length")
                return
            if length <= 0:
                self._error(400, "request body is required")
                return
            if length > 64 * 1024:
                self._error(413, "request exceeds 64 KiB")
                return

            self.connection.settimeout(bounded_timeout)
            try:
                body = self.rfile.read(length)
            except TimeoutError:
                self._error(408, "request body timed out")
                return
            except OSError:
                self._error(400, "request body could not be read")
                return
            if len(body) != length:
                self._error(400, "incomplete request body")
                return

            try:
                event = verifier.verify(self.headers, body)
            except CollectorAuthenticationError:
                self._error(401, "authentication failed")
                return
            except CollectorReplayError:
                self._error(409, "duplicate event")
                return
            except CollectorPayloadError:
                self._error(400, "invalid event envelope")
                return

            try:
                store.append(event)
            except OSError:
                verifier.release_replay(event)
                self._error(503, "storage unavailable")
                return
            self._reply(202, {"accepted": True, "event_id": event["event_id"]})

        def _error(self, status: int, message: str) -> None:
            self._reply(status, {"accepted": False, "error": message})

        def _reply(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                return

        def log_message(self, format: str, *args) -> None:
            return

    return Handler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the OT Sentinel central event collector")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--credentials", required=True, help="JSON object mapping sensor IDs to secrets")
    parser.add_argument("--output", default="logs/collector-events.jsonl")
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--allow-insecure-loopback", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    credentials = json.loads(Path(args.credentials).read_text(encoding="utf-8"))
    verifier = CollectorVerifier(credentials)
    server = CollectorHTTPServer(
        (args.host, args.port), make_handler(verifier, CollectorStore(Path(args.output)))
    )
    if args.tls_cert and args.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    elif not (args.allow_insecure_loopback and args.host in {"127.0.0.1", "::1", "localhost"}):
        raise SystemExit("TLS certificate and key are required outside an explicit loopback lab.")
    scheme = "https" if args.tls_cert else "http"
    print(f"OT Sentinel collector listening on {scheme}://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
