"""Metric computation: bootstrap intervals, attack success rate, detector quality.

Confidence intervals come from a seeded nonparametric bootstrap rather than a
normal approximation, because attack success rates sit near 0 or 1 for some
families where the normal approximation is poor. The seed makes the interval
reproducible to the digit.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Sequence

from pydantic import BaseModel

from veritas.harness.types import EvalRecord, FamilyResult, Interval, ModelResult

BOOTSTRAP_RESAMPLES = 1000


def bootstrap_interval(outcomes: Sequence[bool], *, seed: int, resamples: int = BOOTSTRAP_RESAMPLES,
                       confidence: float = 0.95) -> Interval:
    """Return the mean of ``outcomes`` with a percentile bootstrap interval."""
    n = len(outcomes)
    if n == 0:
        return Interval(estimate=0.0, low=0.0, high=0.0, n=0)
    point = sum(outcomes) / n
    rng = random.Random(seed)
    means: list[float] = []
    values = [1 if o else 0 for o in outcomes]
    for _ in range(resamples):
        sample = (values[rng.randrange(n)] for _ in range(n))
        means.append(sum(sample) / n)
    means.sort()
    tail = (1.0 - confidence) / 2.0
    low = means[int(tail * resamples)]
    high = means[min(int((1.0 - tail) * resamples), resamples - 1)]
    return Interval(estimate=round(point, 4), low=round(low, 4), high=round(high, 4), n=n)


def summarise_model(model: str, records: list[EvalRecord], *, seed: int) -> ModelResult:
    """Aggregate per-case records into an attack-success summary for one model."""
    successes = [r.attack_success for r in records]
    by_family: dict[str, list[EvalRecord]] = defaultdict(list)
    for r in records:
        by_family[r.family].append(r)
    family_results = [
        FamilyResult(
            family=family, n=len(items), successes=sum(r.attack_success for r in items),
            asr=bootstrap_interval([r.attack_success for r in items], seed=seed))
        for family, items in sorted(by_family.items())
    ]
    mean_latency = sum(r.latency_ms for r in records) / len(records) if records else 0.0
    refusals = sum(r.refused for r in records) / len(records) if records else 0.0
    return ModelResult(
        model=model, n_cases=len(records),
        attack_success_rate=bootstrap_interval(successes, seed=seed),
        refusal_rate=round(refusals, 4), mean_latency_ms=round(mean_latency, 4),
        by_family=family_results)


class DetectorMetrics(BaseModel):
    """Precision, recall and false-positive rate for the guardrail classifier."""

    true_positives: int
    false_negatives: int
    false_positives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    hard_negative_fp_rate: float


def detector_metrics(attack_flags: list[bool], benign_flags: list[bool],
                     hard_negative_flags: list[bool]) -> DetectorMetrics:
    """Compute classifier quality from flag outcomes on attacks and benign prompts."""
    tp = sum(attack_flags)
    fn = len(attack_flags) - tp
    fp = sum(benign_flags)
    tn = len(benign_flags) - fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / len(benign_flags) if benign_flags else 0.0
    hard_fpr = (sum(hard_negative_flags) / len(hard_negative_flags)
                if hard_negative_flags else 0.0)
    return DetectorMetrics(
        true_positives=tp, false_negatives=fn, false_positives=fp, true_negatives=tn,
        precision=round(precision, 4), recall=round(recall, 4), f1=round(f1, 4),
        false_positive_rate=round(fpr, 4), hard_negative_fp_rate=round(hard_fpr, 4))
