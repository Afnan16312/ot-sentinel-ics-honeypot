# Collector Threat Model

## Scope and security objective

This model covers the framework-free HTTP collector in `src/ot_sentinel/collector.py`, the signed sender in `src/ot_sentinel/transport.py`, local private JSONL storage and the optional TLS boundary. It does not cover the Oracle live sensor, a production SIEM, analyst identity management or public telemetry publication.

The objective is narrow: accept one bounded event from a configured sensor only when the exact body is fresh, correctly signed and identity-consistent; append it once to private storage; and reveal no request or storage details in an error response.

## Assets

| Asset | Security need |
|---|---|
| Per-sensor HMAC secrets | Confidentiality and controlled rotation |
| Private event envelopes | Confidentiality, integrity and retention control |
| Event and session identifiers | Integrity and replay uniqueness |
| Collector credentials file | Confidentiality and least-privilege access |
| TLS private key and certificate | Key confidentiality, authenticity and availability |
| Replay cache | Integrity and bounded availability |
| JSONL output | Append integrity, durability, capacity and recoverability |
| OpenAPI contract and code | Version integrity and reproducibility |

## Trust boundaries

1. **Network client to TLS endpoint:** untrusted connections, headers and bytes cross into the collector service.
2. **TLS endpoint to Python handler:** a direct TLS socket or approved proxy forwards a bounded HTTP request; proxy-added identity is not trusted by the application.
3. **HTTP handler to verifier:** the exact body and authentication headers enter HMAC, freshness, schema and identity checks.
4. **Verifier to replay cache:** an authenticated sensor/event identifier enters synchronized process memory.
5. **Verifier to private JSONL:** an authenticated event crosses into filesystem storage under a process identity.
6. **Health endpoint to monitoring:** a minimal liveness signal crosses back to an operator or gateway; it contains no telemetry or secret state.

## Threat actors

- Opportunistic Internet scanners and malformed clients.
- A client that knows a sensor identifier but not its HMAC secret.
- A compromised or misconfigured sensor with one valid per-sensor secret.
- An on-path observer when TLS is absent, invalid or terminated incorrectly.
- A local process or account able to read credentials or write collector storage.
- A dependency, build or host compromise affecting the Python runtime or deployment environment.
- An authorized operator who makes an accidental configuration, retention or certificate error.

## Threat analysis

| Threat | Attack path | Existing mitigation | Residual risk |
|---|---|---|---|
| Spoofing | Claim a configured sensor ID | Per-sensor secret, exact-body HMAC, constant-time comparison, generic HTTP authentication failure | A stolen sensor secret permits that sensor's identity until rotation |
| Tampering | Modify body, timestamp or identity fields | HMAC covers timestamp, newline and exact body; envelope/event identity must match header | A compromised sensor can sign false events under its own identity |
| Replay | Resend a captured valid envelope | Freshness window plus synchronized sensor/event replay cache; concurrent replay accepts once | Replay memory is process-local and resets on restart; durable cross-restart replay protection is not provided |
| Denial of service | Slow body, oversized request, connection flood or replay flood | 64 KiB body cap, required single length, bounded body timeout, thread-safe replay/store operations | Standard-library threaded server has no distributed rate limit or global connection cap |
| Information disclosure | Cause errors that echo body, secret, identifier, path or traceback | Fixed JSON error messages, no request echo, no handler access log, no-store and nosniff headers | Host/proxy/runtime logs and crash output still require separate redaction controls |
| Storage failure | Fill disk, remove permission or interrupt append | Locked one-line append; storage failure returns generic 503 and releases replay reservation for retry | JSONL is not transactional, tamper-evident or replicated; partial host/filesystem failure remains possible |
| Certificate failure | Expired, mismatched, missing or unreadable certificate | TLS required outside explicit loopback; TLS 1.2 minimum for direct termination | Rotation, expiry alerting, revocation and proxy configuration are operator responsibilities |
| Dependency/supply chain | Malicious or vulnerable framework/package/build | Collector runtime uses the Python standard library and project code only; CI, CodeQL, audit, SBOM and container scan provide evidence | Python, base OS, CI actions and build infrastructure remain dependencies that require patching and review |

## Security behavior proved by synthetic black-box tests

- Correct signed request returns 202 and is appended once.
- Bad HMAC, unknown identity, missing authentication, stale/future time and identity mismatch return a generic 401.
- Replay returns 409; synchronized concurrent replay accepts exactly one request.
- Malformed JSON, invalid or incomplete length and empty bodies are rejected.
- Non-JSON content returns 415 and a declared body above 64 KiB returns 413 before body processing.
- Slow incomplete body processing reaches a bounded 408 response.
- Concurrent distinct valid requests are stored without line loss.
- Storage failure returns a redacted 503 and permits an authenticated retry.
- Health remains a compatible minimal 200 response and shutdown completes cleanly.

Evidence: `tests/test_collector_blackbox.py` and `tests/test_transport.py`.

## Residual-risk decisions

The current collector is intentionally not an identity platform, case-management database, message broker or Internet-scale API gateway. A production deployment needs an approved TLS gateway, connection/rate limits, process supervision, resource controls, protected storage, monitoring and recovery procedures described in [Collector Operational Hardening](COLLECTOR_HARDENING.md).

The collector should remain private and must never be placed on the same network as production OT. HMAC does not replace TLS, host security, secret rotation or source governance.
