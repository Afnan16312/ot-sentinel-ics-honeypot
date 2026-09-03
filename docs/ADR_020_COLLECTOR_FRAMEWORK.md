# ADR-020: Retain the Framework-Free Collector

- **Status:** Accepted
- **Date:** 2026-08-23
- **Scope:** Collector HTTP implementation only

## Context

OT Sentinel needs authenticated machine-to-machine ingestion and process liveness. The current API has exactly two endpoints: `POST /v1/events` and `GET /health`. It does not provide analyst accounts, browser workflows, cases, queries or administrative resources.

The current implementation uses Python's standard-library `ThreadingHTTPServer`, TLS support, bounded request handling, per-sensor HMAC verification, timestamp freshness, identity consistency, synchronized replay detection and locked JSONL append. Synthetic black-box tests exercise the API through real loopback sockets rather than only calling verifier functions.

## Options considered

| Option | Advantages | Costs and risks | Fit now |
|---|---|---|---|
| Existing framework-free collector | Small dependency surface; direct control of exact-body signing and limits; easy to audit; low memory; no framework patch stream | Manual HTTP controls; no routing ecosystem, middleware, ORM, identity system or built-in operational dashboard | Best fit for two machine endpoints |
| Flask API | Mature routing and middleware ecosystem; easier expansion; broad deployment support | Adds runtime dependencies and WSGI configuration; still needs explicit HMAC, replay, limits, TLS gateway, rate limiting and storage design | Useful if API surface expands, unnecessary now |
| Django + Django REST Framework | Strong models, migrations, authentication/permissions, browsable workflows and mature administrative features | Largest dependency/configuration surface; ORM/database and settings lifecycle; substantially more patching and operational complexity | Appropriate only for a multi-user application or case platform |

## Decision

Retain the existing framework-free collector. Do not add Flask, Django or Django REST Framework at this stage.

The decision is based on API shape, not a claim that frameworks are insecure. With only two endpoints, the current collector already implements the necessary application controls, and its behavior is now covered by direct black-box concurrency, malformed-input, authentication, replay, timeout, storage-failure, privacy and shutdown tests.

## Consequences

### Positive

- The exposed runtime remains standard-library only.
- HMAC verification continues to operate on the exact received bytes without middleware transformation ambiguity.
- Dependency audit and upgrade work remain smaller.
- A reviewer can follow the complete request path in one compact module.

### Negative

- HTTP and operational controls must be deliberately tested and maintained.
- The collector has no user authentication, authorization roles, database migrations, query API, rate limiter or case workflow.
- Scaling beyond one small process requires an external gateway and a deliberate storage/queue architecture.

## Framework-migration triggers

Revisit this ADR when one or more of these conditions becomes real rather than hypothetical:

1. Multiple complex API resources or versioned resource relationships.
2. Analyst accounts and role-based permissions.
3. Browser-based workflows or an authenticated analyst interface.
4. Case-management data, comments, assignments or audit history.
5. Significant external SIEM/SOAR consumers requiring lifecycle, pagination, filtering or tenant controls.
6. Scaling or reliability requirements the current threaded collector and JSONL store cannot safely handle.

## Migration rule

A future framework proposal must preserve the existing OpenAPI behavior or publish a versioned replacement, verify HMAC against exact bytes, retain replay and privacy guarantees, run old and new paths in parallel during migration, and include a tested rollback. Framework adoption alone does not satisfy TLS, rate limiting, secret management, durable storage or observability requirements.

## Evidence

- `src/ot_sentinel/collector.py`
- `src/ot_sentinel/transport.py`
- `tests/test_collector_blackbox.py`
- `tests/test_transport.py`
- `docs/api/collector.openapi.json`
- [Collector Threat Model](COLLECTOR_THREAT_MODEL.md)
- [Collector Operational Hardening](COLLECTOR_HARDENING.md)
