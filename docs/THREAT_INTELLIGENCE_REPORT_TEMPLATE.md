# OT Sentinel Threat-Intelligence Report Template

Use this template only after the collection window ends and a privacy review approves aggregate publication.

## Report title

OT Sentinel: Internet Activity Observed by an ICS Decoy in [cloud region], [start date] to [end date]

## Data notice

State whether the report uses synthetic demonstration data or reviewed sanitized observations. Never mix the two categories.

## Executive summary

- Study purpose:
- Authorized collection window:
- Sensor region:
- Total protocol events:
- Important limitations:

## Method

- Low-interaction services exposed:
- Safety and isolation controls:
- Event normalization method:
- Privacy and aggregation method:
- ATT&CK mapping standard:

## Findings

- Activity by protocol:
- Activity by day:
- Evidence-qualified ATT&CK techniques:
- Control-operation attempts:
- Data-quality observations:

## Interpretation limits

- An IP address does not identify a person or prove malicious intent.
- The sensor's cloud region does not establish an attacker's physical location.
- A connection alone is not exploitation.
- Honeypot observations are biased by exposure, realism, address reputation and collection length.

## Defensive recommendations

Provide control-focused recommendations without publishing exploitable infrastructure details or enabling retaliation.

## Privacy review

- [ ] No raw IP addresses or network prefixes
- [ ] No raw payloads or credentials
- [ ] No keys, OCIDs or cloud identifiers
- [ ] Small-count disclosure reviewed
- [ ] Automated public-data validator passed
- [ ] Human technical and ethics review completed

## Reproducibility

List the repository release, aggregate-summary schema, detection-pack version and validation commands used. Do not include private evidence paths or secrets.
