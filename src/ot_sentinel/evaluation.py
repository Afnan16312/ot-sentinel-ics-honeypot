"""Reproducible multilabel evaluation for the ATT&CK mapper."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .mapper import map_event


@dataclass(frozen=True)
class TechniqueMetrics:
    technique_id: str
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    f1: float
    support: int


@dataclass(frozen=True)
class EvaluationResult:
    cases: int
    exact_matches: int
    exact_match_ratio: float
    micro_precision: float
    micro_recall: float
    micro_f1: float
    macro_f1: float
    techniques: tuple[TechniqueMetrics, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_labeled_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Load labeled mapper cases from JSON Lines."""

    cases: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            case = json.loads(line)
            if "expected_technique_ids" not in case:
                raise ValueError(f"line {line_number} has no expected_technique_ids")
            cases.append(case)
    return cases


def evaluate_mapper(cases: Iterable[Mapping[str, Any]]) -> EvaluationResult:
    """Evaluate mapper predictions against human-authored expected labels.

    Metrics are calculated over the technique labels present in either the
    expected or predicted sets. Precision and recall use a zero-safe definition.
    """

    rows: list[tuple[set[str], set[str]]] = []
    label_universe: set[str] = set()
    for case in cases:
        expected = {str(item) for item in case.get("expected_technique_ids", [])}
        predicted = {
            match.technique_id
            for match in map_event(
                str(case.get("protocol", "unknown")),
                str(case.get("event_type", "connection")),
                dict(case.get("decoded") or {}),
            )
        }
        rows.append((expected, predicted))
        label_universe.update(expected | predicted)

    metrics: list[TechniqueMetrics] = []
    for technique_id in sorted(label_universe):
        tp = sum(technique_id in expected and technique_id in predicted for expected, predicted in rows)
        fp = sum(technique_id not in expected and technique_id in predicted for expected, predicted in rows)
        fn = sum(technique_id in expected and technique_id not in predicted for expected, predicted in rows)
        tn = len(rows) - tp - fp - fn
        precision = _ratio(tp, tp + fp)
        recall = _ratio(tp, tp + fn)
        f1 = _f1(precision, recall)
        metrics.append(
            TechniqueMetrics(
                technique_id=technique_id,
                true_positive=tp,
                false_positive=fp,
                false_negative=fn,
                true_negative=tn,
                precision=precision,
                recall=recall,
                f1=f1,
                support=tp + fn,
            )
        )

    total_tp = sum(item.true_positive for item in metrics)
    total_fp = sum(item.false_positive for item in metrics)
    total_fn = sum(item.false_negative for item in metrics)
    micro_precision = _ratio(total_tp, total_tp + total_fp)
    micro_recall = _ratio(total_tp, total_tp + total_fn)
    exact_matches = sum(expected == predicted for expected, predicted in rows)
    return EvaluationResult(
        cases=len(rows),
        exact_matches=exact_matches,
        exact_match_ratio=_ratio(exact_matches, len(rows)),
        micro_precision=micro_precision,
        micro_recall=micro_recall,
        micro_f1=_f1(micro_precision, micro_recall),
        macro_f1=_ratio(sum(item.f1 for item in metrics), len(metrics)),
        techniques=tuple(metrics),
    )


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _f1(precision: float, recall: float) -> float:
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0
