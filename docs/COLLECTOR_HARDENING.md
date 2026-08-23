# Collector Operational Hardening

This document describes production considerations for the optional collector. It is design guidance only. Nothing in this document was deployed to Oracle or any other environment as part of the collector-assurance task.

## Recommended boundary

Keep the Python collector on a private loopback or service network behind an approved TLS reverse proxy or API gateway. Expose only the gateway. Do not expose the collector, private JSONL, health details or credentials to an untrusted network, and never connect this path to production OT.

## TLS termination

- Terminate TLS with an approved gateway or use the collector's direct TLS mode for a small controlled deployment.
- Require TLS 1.2 or newer, a trusted certificate chain and hostname verification.
- Restrict gateway-to-collector traffic to loopback or a dedicated private service network.
- If a proxy terminates TLS, ensure it forwards the exact request body without decompression, transcoding or JSON rewriting because HMAC covers exact bytes.
- Consider mutual TLS as an additional transport identity control; do not remove per-sensor HMAC without a separate design decision.

## Reverse proxy or gateway

- Allow only `POST /v1/events` and `GET /health`; reject all other methods and paths.
- Set independent header, body, connection, read and idle limits no weaker than the application limits.
- Disable request-body logging and redact the three authentication headers.
- Do not trust client-supplied forwarding headers unless the gateway overwrites them.
- Keep the backend collector inaccessible except from the gateway identity/network.

## Rate limiting

- Apply limits per source connection and per configured sensor identity after careful load measurement.
- Add a conservative global concurrent-connection cap and request-rate ceiling.
- Return bounded errors without echoing identifiers or bodies.
- Monitor rejection counts separately from accepted-event counts.
- Do not implement a limit that blocks legitimate retry after a documented storage or gateway failure.

## Process supervision

- Run under systemd, a container orchestrator or another approved supervisor with a dedicated unprivileged identity.
- Use a read-only application filesystem and grant write access only to the private output directory.
- Restart on unexpected failure with bounded backoff; avoid tight crash loops.
- Send SIGTERM, stop accepting new requests, allow bounded in-flight completion, then close storage cleanly.
- Test restart, host reboot and shutdown behavior before production acceptance.

## Certificate rotation

- Inventory certificate owner, issuer, hostname, expiry and private-key location.
- Alert well before expiry and rehearse rotation in a non-production environment.
- Load the new certificate atomically or use gateway hot reload; verify new connections before retiring the old material.
- Keep private keys outside Git with restrictive permissions and an approved backup/recovery method.
- Document emergency rotation after key exposure.

## Resource limits

- Cap memory, CPU, processes/threads, open files, request body and connection duration.
- Reserve sufficient disk for the retention window and alert on both percentage and absolute free space.
- Keep the 64 KiB application body limit even when the gateway has a larger generic limit.
- Load-test only with synthetic events in an isolated environment before setting production capacity claims.

## Structured redacted logging

Record operational facts such as timestamp, request outcome class, status code, latency and a non-sensitive correlation identifier. Never log request bodies, signatures, HMAC secrets, raw source addresses, credentials, certificate keys or private output paths. Treat proxy, runtime and crash logs as private operational data with retention limits.

## Health monitoring

`GET /health` is liveness only. Monitor it through the private gateway and separately monitor:

- successful and rejected request rates by status class;
- body timeout, replay and storage-unavailable counts;
- process restarts, thread/connection pressure and latency;
- certificate expiry and TLS handshake failures;
- output-file growth, disk space and last successful append;
- backup age and restore-test status.

Do not add sensor identities, source data or secret state to the public health response.

## Backup and recovery

- Define retention, encryption, access approval and deletion requirements before collection.
- Back up private JSONL to approved encrypted storage without committing it to Git.
- Record checksums and collection windows separately from public reports.
- Test restoration into an isolated analysis location and verify complete line boundaries.
- Document recovery point and recovery time objectives; JSONL alone does not provide replication or tamper evidence.

## Zero-interruption migration

1. Freeze and version the current OpenAPI contract.
2. Build the replacement using synthetic fixtures only.
3. Replay a sanitized/synthetic conformance corpus against both implementations.
4. Shadow traffic only after governance approval, with the new path unable to write authoritative data.
5. Compare acceptance, rejection, latency and privacy behavior.
6. Enable dual write only with idempotent event IDs and reconciliation.
7. Move a small controlled sensor group, observe, then expand gradually.
8. Keep the old collector available until all acceptance and recovery gates pass.

## Rollback procedure

1. Stop routing new requests to the candidate collector.
2. Restore routing to the last verified collector and credential set.
3. Confirm `GET /health`, one synthetic signed POST and storage append.
4. Reconcile event IDs produced during the migration window without publishing private data.
5. Preserve redacted operational evidence and record the rollback reason.
6. Rotate credentials or certificates if the migration failure involved possible exposure.

Rollback must not silently discard accepted events or weaken authentication to restore availability.

## Production acceptance gate

Do not call the collector production-ready until the exact deployment has passed native TLS/gateway configuration validation, synthetic load and failure testing, restore testing, secret/certificate rotation rehearsal, monitoring alerts and an approved privacy/retention review.
