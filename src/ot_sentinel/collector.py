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
            raise CollectorError("request exceeds 64 KiB")
        normalized_headers = {str(key).lower(): str(value) for key, value in headers.items()}
        sensor_id = normalized_headers.get("x-ot-sensor", "")
        timestamp = normalized_headers.get("x-ot-timestamp", "")
        provided = normalized_headers.get("x-ot-signature", "")
        secret = self.sensor_secrets.get(sensor_id)
        if secret is None:
            raise CollectorError("unknown sensor")
        try:
            numeric_timestamp = int(timestamp)
        except ValueError as exc:
            raise CollectorError("invalid timestamp") from exc
        if abs(time.time() - numeric_timestamp) > self.max_clock_skew:
            raise CollectorError("timestamp outside accepted window")
        expected = "sha256=" + canonical_signature(secret, timestamp, body)
        if not hmac.compare_digest(provided, expected):
            raise CollectorError("invalid signature")
        try:
            envelope = json.loads(body)
        except json.JSONDecodeError as exc:
            raise CollectorError("invalid JSON") from exc
        if not isinstance(envelope, dict):
            raise CollectorError("envelope must be a JSON object")
        if envelope.get("schema") != "ot-sentinel-envelope/1":
            raise CollectorError("unsupported envelope schema")
        if envelope.get("sensor_id") != sensor_id:
            raise CollectorError("sensor identity mismatch")
        event = envelope.get("event")
        if not isinstance(event, dict) or event.get("sensor_id") != sensor_id:
            raise CollectorError("event sensor identity mismatch")
        required = {"event_id", "session_id", "observed_at", "protocol", "event_type"}
        if not required.issubset(event):
            raise CollectorError("event is missing required fields")
        replay_key = f"{sensor_id}:{event['event_id']}"
        now = time.monotonic()
        with self._lock:
            self._seen = {
                key: observed for key, observed in self._seen.items() if now - observed < 900
            }
            if replay_key in self._seen:
                raise CollectorError("duplicate event")
            self._seen[replay_key] = now
        return {
            "received_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "transport_authenticated": True,
            "envelope_sent_at": envelope.get("sent_at"),
            **event,
        }


class CollectorStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def make_handler(verifier: CollectorVerifier, store: CollectorStore):
    class Handler(BaseHTTPRequestHandler):
        server_version = "OTSentinelCollector/0.2"

        def do_GET(self) -> None:
            if self.path != "/health":
                self.send_error(404)
                return
            self._reply(200, {"status": "ok"})

        def do_POST(self) -> None:
            if self.path != "/v1/events":
                self.send_error(404)
                return
            try:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError as exc:
                    raise CollectorError("invalid content length") from exc
                if not 0 < length <= 64 * 1024:
                    raise CollectorError("invalid content length")
                self.connection.settimeout(5.0)
                body = self.rfile.read(length)
                if len(body) != length:
                    raise CollectorError("incomplete request body")
                event = verifier.verify(self.headers, body)
                store.append(event)
            except (CollectorError, TimeoutError) as exc:
                self._reply(401, {"accepted": False, "error": str(exc)})
                return
            self._reply(202, {"accepted": True, "event_id": event["event_id"]})

        def _reply(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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
    server = ThreadingHTTPServer(
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
