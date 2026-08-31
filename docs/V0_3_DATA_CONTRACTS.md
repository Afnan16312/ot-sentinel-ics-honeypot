# v0.3 Data Contracts

OT Sentinel v0.3 separates immutable capture evidence from repeatable interpretation.

- **Observation v1** is the sensor or collector record. It identifies the session, protocol action and bounded decoded evidence, but never contains ATT&CK mappings, severity, triage or rule results.
- **Analysis v1** references one observation by `event_id` and `input_digest`. It records the mapper, triage and rule-catalog versions used for that interpretation.
- **Legacy v0** JSONL remains unchanged. `scripts/migrate_contracts.py INPUT OBSERVATIONS_OUTPUT ANALYSES_OUTPUT --dry-run` reports how many observation and analysis records would be derived before writing either new file. Omit `--dry-run` only after reviewing those counts.

The raw JSONL record remains authoritative private evidence. The optional SQLite index stores versioned analysis results so an improved mapper can be run again without rewriting the observation. Public outputs still require the existing privacy gate and human review.
