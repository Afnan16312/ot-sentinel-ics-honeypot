# STIX 2.1 export

OT Sentinel can package its JSONL events as a STIX 2.1 Bundle for sharing with threat-intelligence tools. The export preserves the distinction between observed evidence and an ATT&CK mapping hypothesis.

## Public profile

Use this profile for portfolio artifacts, reports and community sharing:

```powershell
$env:OT_PRIVACY_SALT = "replace-with-a-long-private-random-value"
ot-sentinel export-stix data\events.jsonl output\events-public.stix.json --profile public
```

The salt is needed only when the input still contains `source_ip`. It must be private and contain at least 32 characters. Already-sanitized events containing a safe `source_id` can be exported without it.

The public profile:

- replaces a raw source address with a salted `source_id`;
- never exports `source_ip`, source network prefixes or payload bytes;
- rejects a pre-existing `source_id` if it embeds an address;
- rejects credential-like fields and mixed synthetic/observed input;
- uses a strict allowlist for decoded protocol metadata;
- labels each observation as `synthetic` or `live` using `is_demo`;
- carries confidence and rationale on each ATT&CK relationship.

Keep the salt private and stable for one research period. Changing it prevents correlation between releases, while reusing it forever increases linkability.

## Private profile

Use this only in a restricted analyst environment:

```powershell
ot-sentinel export-stix data\events-private.jsonl output\events-private.stix.json --profile private
```

This profile preserves the source as a standard `ipv4-addr` or `ipv6-addr` Cyber-observable Object. When a raw payload exists, it is represented as an `artifact` with Base64 bytes and a SHA-256 hash. Do not publish a private Bundle.

## Object model

| STIX object | OT Sentinel use |
|---|---|
| `identity` | Names OT Sentinel as the Bundle producer |
| `network-traffic` | Records TCP transport, ports and byte count |
| `domain-name` | Non-routable `.invalid` placeholder for a public source pseudonym |
| `observed-data` | Carries one normalized event, ICS protocol and evidence metadata |
| `ipv4-addr` / `ipv6-addr` | Private-profile source evidence only |
| `artifact` | Private-profile payload evidence only |
| `attack-pattern` | References a MITRE ATT&CK for ICS technique by external ID and URL |
| `relationship` | Connects evidence to a technique as an evidence-based hypothesis |
| `grouping` | States export profile and synthetic/live dataset classification |

Technique relationships use `related-to`, not `indicates`. A honeypot request is evidence for an analytical hypothesis; it is not a reusable STIX Indicator pattern and does not prove attribution or compromise.

## Interoperability notes

- The output follows the STIX 2.1 Bundle and object shapes and uses STIX custom properties prefixed with `x_ot_sentinel_`.
- OASIS recommends its newer Extension Definition mechanism for custom properties. Flat `x_ot_sentinel_*` properties remain schema-valid and broadly compatible, but a strict best-practice validator will warn about them.
- IDs are deterministic UUIDv5 values to make repeated exports reproducible and deduplicable. The object type is included in the ID material to prevent cross-type UUID reuse. STIX 2.1 recommends UUIDv5 for Cyber-observable Objects. It recommends UUIDv4 for other object categories, but UUIDv5 remains syntactically valid; consumers with a stricter local policy may choose to replace non-SCO IDs during ingestion.
- MITRE technique objects are local references with `external_references`. They are not claimed to be MITRE's canonical STIX objects or canonical MITRE object UUIDs.
- Importers that disable custom STIX properties must enable custom-property support or discard the `x_ot_sentinel_*` fields.
- Public-profile safety is enforced during export and by a second independent bundle gate. A Bundle is rejected if a payload/credential field or any address/network literal survives serialization. Streamlit invokes the bundle gate again immediately before enabling its public download.

The exporter uses only Python's standard library, so it does not add a package or hosted-service cost.

## References

- [OASIS STIX 2.1 standard](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
