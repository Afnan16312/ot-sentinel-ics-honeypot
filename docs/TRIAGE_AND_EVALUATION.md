# Analyst triage and mapper evaluation

OT Sentinel ranks evidence for review and measures whether its ATT&CK mapper still behaves as designed. These controls improve consistency; they do not identify an attacker or prove harmful intent, attribution, exploitation, or compromise.

## Triage score

`src/ot_sentinel/triage.py` assigns each event a deterministic score from 0 to 100. The score ignores country, IP identity, and other attribution-like data. It uses only recorded protocol evidence:

| Evidence | Points | Why it matters |
| --- | ---: | --- |
| Protocol-aware probe | 10 | A request interacted with an ICS service rather than only opening TCP. |
| Process or I/O read | 15 | A request read simulated operational state. |
| Control command | 40 | A request carried an operation able to change decoy state. |
| Program transfer | 45 | A controller program-transfer operation was recorded. |
| Configured exploit signature | 35 | Captured bytes matched a known signature configured by the project. |
| Strongest ATT&CK mapping: low / medium / high | 5 / 10 / 20 | The event contains an evidence-qualified mapping at that confidence. |

Points are additive and capped at 100. Each result includes its factors, points, explanations, and an analyst note.

| Score | Queue |
| ---: | --- |
| 0 | Informational |
| 1–24 | Routine review |
| 25–49 | Elevated review |
| 50–74 | High review |
| 75–100 | Urgent review |

The queue is a review order, not a verdict. Analysts must inspect the attached evidence.

## Mapper evaluation

`src/ot_sentinel/evaluation.py` replays human-authored cases from `tests/fixtures/evaluation/mapper_cases.jsonl`. Each case contains protocol input and the ATT&CK technique IDs expected from that evidence. The evaluator reports:

- exact-match ratio across cases;
- micro precision, recall, and F1 across all labels;
- macro F1 across represented techniques;
- TP, FP, FN, TN, precision, recall, F1, and support for each represented technique.

Run the benchmark with the normal test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

The bundled golden fixture is deliberately small and deterministic. A perfect score means the mapper agrees with these regression labels; it is **not** evidence of perfect performance on real traffic. Expanding the labeled set with independently reviewed, authorized observations is required before making broader accuracy claims.

## Dashboard use

Open **TRIAGE & VALIDATION** to see the review queue, point-by-point explanations, score distribution, regression metrics, and per-technique confusion counts. Dashboard filters also apply to the triage queue. The evaluation card always describes the fixed fixture so that operational telemetry is not confused with benchmark data.
