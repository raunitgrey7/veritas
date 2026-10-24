"""The guardrail pipeline: compose detectors into input and output verdicts.

The pipeline is the product surface. Input detectors score an incoming prompt;
output scanners score a model response. A verdict aggregates the per-detector
signals into one decision with a risk score and human-readable reasons, so the
API and the dashboard can show why a prompt was blocked. Thresholds are explicit
and tunable, not hidden magic numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from veritas.detectors.base import Detector, Signal, Verdict
from veritas.detectors.encoding import EncodingDetector
from veritas.detectors.output_scanners import CanaryScanner, PIIScanner, SecretScanner
from veritas.detectors.patterns import PatternDetector
from veritas.detectors.structural import InstructionHierarchyDetector, StructuralDetector

# A prompt at or above BLOCK risk is rejected; between FLAG and BLOCK it is
# allowed but marked for review; below FLAG it is allowed.
FLAG_THRESHOLD = 0.5
BLOCK_THRESHOLD = 0.8


@dataclass(frozen=True)
class GuardVerdict:
    """Aggregate decision over a set of detector signals."""

    verdict: Verdict
    risk: float
    signals: tuple[Signal, ...] = field(default_factory=tuple)

    @property
    def flagged(self) -> bool:
        """True when the prompt is not plainly allowed."""
        return self.verdict is not Verdict.ALLOW

    @property
    def categories(self) -> list[str]:
        return sorted({s.category for s in self.signals})

    @property
    def reasons(self) -> list[str]:
        seen: dict[str, None] = {}
        for s in self.signals:
            seen.setdefault(f"[{s.detector}] {s.explanation}", None)
        return list(seen)


def input_detectors() -> list[Detector]:
    """The detectors that score an incoming prompt."""
    return [PatternDetector(), StructuralDetector(),
            InstructionHierarchyDetector(), EncodingDetector()]


def output_detectors() -> list[Detector]:
    """The scanners that score a model response."""
    return [SecretScanner(), PIIScanner(), CanaryScanner()]


def _aggregate(signals: list[Signal]) -> GuardVerdict:
    risk = max((s.score for s in signals), default=0.0)
    if risk >= BLOCK_THRESHOLD:
        verdict = Verdict.BLOCK
    elif risk >= FLAG_THRESHOLD:
        verdict = Verdict.FLAG
    else:
        verdict = Verdict.ALLOW
    ordered = tuple(sorted(signals, key=lambda s: s.score, reverse=True))
    return GuardVerdict(verdict=verdict, risk=risk, signals=ordered)


class Guardrail:
    """Run the detector suite over inputs and outputs.

    The suite is fixed by default but injectable for testing. ``evaluate_input``
    and ``evaluate_output`` both return a :class:`GuardVerdict` so callers treat
    them uniformly.
    """

    def __init__(self, inputs: list[Detector] | None = None,
                 outputs: list[Detector] | None = None) -> None:
        self._inputs = inputs if inputs is not None else input_detectors()
        self._outputs = outputs if outputs is not None else output_detectors()

    def evaluate_input(self, text: str, *, canary: str | None = None) -> GuardVerdict:
        """Score an incoming prompt across all input detectors."""
        signals: list[Signal] = []
        for det in self._inputs:
            signals.extend(det.scan(text, canary=canary).signals)
        return _aggregate(signals)

    def evaluate_output(self, text: str, *, canary: str | None = None) -> GuardVerdict:
        """Score a model response across all output scanners."""
        signals: list[Signal] = []
        for det in self._outputs:
            signals.extend(det.scan(text, canary=canary).signals)
        return _aggregate(signals)
