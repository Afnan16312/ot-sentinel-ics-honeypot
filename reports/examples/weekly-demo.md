# Weekly OT Threat Intelligence Brief

> **Data notice:** Synthetic demonstration statistics; not observed attacker activity.

## Reporting window

2026-07-08T00:00:00+00:00 to 2026-07-15T00:00:00+00:00 (UTC)

## Summary

- Total sessions represented: **199**
- Total events including repetitions: **201**
- Source pseudonyms do not identify people or organizations.
- ATT&CK mappings are evidence-qualified hypotheses, not proof of intent or compromise.

## Protocol breakdown

| Protocol | Events |
|---|---:|
| modbus | 91 |
| s7 | 54 |
| iec104 | 56 |

## Top ATT&CK for ICS techniques

| Technique | Observations | Confidence distribution |
|---|---:|---|
| T0846.001 | 123 | medium: 123 |
| T0836 | 65 | medium: 65 |
| T1692.001 | 65 | high: 65 |
| T0877 | 53 | low: 53 |
| T0843 | 13 | high: 13 |

## Top private pseudonymous sources

| Salted pseudonym | Sessions |
|---|---:|
| src-e45d950967f6 | 24 |
| src-e9936b58b1d5 | 24 |
| src-2aac642f0d35 | 23 |
| src-396eadc9dfdc | 23 |
| src-65c55a0153a7 | 19 |

## Methodology

Counts come from OT Sentinel's privacy-reduced SQLite analysis index. Repeated source/protocol/payload observations inside the deduplication window contribute through `repeat_count`. JSONL remains the authoritative private evidence.

## Limitations

A honeypot observes only traffic that reaches its exposed decoy. A network source is not an identity, geolocation is approximate, and protocol interaction is not proof of exploitation, attribution or physical impact.
