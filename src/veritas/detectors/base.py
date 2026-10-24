"""Shared types for detectors and the guardrail pipeline.

A detector is anything with a ``name`` and a ``scan`` method that turns text into
a :class:`DetectionResult`. Keeping the contract this small makes detectors easy
to unit test in isolation and easy to compose in the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable


class Verdict(StrEnum):
    """Aggregate decision for a prompt or an output."""

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


@dataclass(frozen=True)
class Signal:
    """One piece of evidence from a detector.

    ``score`` is in ``[0, 1]`` and expresses confidence that this signal is a real
    attack indicator. ``evidence`` is a short, safe excerpt for the explanation;
    it never contains a resolved canary or secret value.
    """

    detector: str
    category: str
    score: float
    explanation: str
    evidence: str = ""


@dataclass(frozen=True)
class DetectionResult:
    """What a single detector reports for one piece of text."""

    detector: str
    signals: tuple[Signal, ...] = field(default_factory=tuple)

    @property
    def flagged(self) -> bool:
        return bool(self.signals)

    @property
    def score(self) -> float:
        return max((s.score for s in self.signals), default=0.0)


@runtime_checkable
class Detector(Protocol):
    """Structural contract every detector satisfies."""

    name: str

    def scan(self, text: str, *, canary: str | None = None) -> DetectionResult:
        """Inspect ``text`` and return any signals found."""
        ...


def result(detector: str, signals: list[Signal]) -> DetectionResult:
    """Build a :class:`DetectionResult`, sorting signals by descending score."""
    ordered = tuple(sorted(signals, key=lambda s: s.score, reverse=True))
    return DetectionResult(detector=detector, signals=ordered)
