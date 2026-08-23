# Safe Public-Summary Pipeline

This pipeline prepares aggregate dashboard statistics without publishing individual records. It was built and tested locally with synthetic fixtures. It has not been connected to the Oracle sensor.

## Current safe workflow

1. Keep raw Oracle JSONL on the private VM.
2. Create a separate sanitized candidate dataset only during an approved publication review.
3. Validate that candidate with `scripts/validate_public_data.py`.
4. Build aggregate counts with `scripts/build_public_summary.py`.
5. Manually review the small summary JSON before publishing it.
6. Keep the public dashboard labeled as synthetic until that review is formally complete.

For the included demonstration data:

```powershell
python scripts/validate_public_data.py data/demo_events.jsonl
python scripts/build_public_summary.py data/demo_events.jsonl data/demo_summary.json
```

The summary contains counts by protocol, event type, severity and ATT&CK technique, plus total event, session and pseudonymous-source counts. It does not contain source identifiers, session identifiers, addresses, payloads, credentials, cloud identifiers or individual event rows.

## Fail-closed controls

- The input must have `sanitized: true` on every record.
- Raw source-address and payload fields are rejected.
- Literal network prefixes are rejected.
- Synthetic and observed records cannot be mixed.
- Observation timestamps are reduced to calendar dates in the aggregate output.
- CI regenerates the synthetic summary and fails if the committed result is not reproducible.

Passing these automated checks is necessary but not sufficient for publishing live research. A human must still review the study window, consent and authorization, geographic wording, small-count disclosure risk and ATT&CK interpretations.

## Live-data boundary

Do not point the summary builder at `logs/events.jsonl`. It accepts only a separately created, reviewed and validated publication candidate. The live sensor does not upload to GitHub, Streamlit or this pipeline automatically.
