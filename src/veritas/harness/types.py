"""Shared value types for the harness: turns, responses and run records.

These are deliberately small and immutable so they serialise cleanly into
``benchmarks/results.json`` and compare cleanly in the regression gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel

Role = Literal["user", "assistant"]


@dataclass(frozen=True)
class Turn:
    """One message in a conversation sent to a model under test."""

    role: Role
    content: str


@dataclass
class ModelResponse:
    """What a model returned, plus provenance used by the judge and metrics."""

    text: str
    model_name: str
    latency_ms: float = 0.0
    metadata: dict[str, str] = field(default_factory=dict)


class Judgement(BaseModel):
    """The deterministic judge's verdict on one response."""

    case_id: str
    success: bool
    refused: bool
    reason: str


class EvalRecord(BaseModel):
    """One (model, case) evaluation, the atom the metrics aggregate over."""

    model: str
    case_id: str
    family: str
    category: str
    variant: str
    language: str
    severity: str
    attack_success: bool
    refused: bool
    input_flagged: bool
    input_risk: float
    latency_ms: float


class Interval(BaseModel):
    """A point estimate with a bootstrap confidence interval."""

    estimate: float
    low: float
    high: float
    n: int


class FamilyResult(BaseModel):
    """Attack success rate for one family, with its confidence interval."""

    family: str
    n: int
    successes: int
    asr: Interval


class ModelResult(BaseModel):
    """Everything measured for one model over the whole corpus."""

    model: str
    n_cases: int
    attack_success_rate: Interval
    refusal_rate: float
    mean_latency_ms: float
    by_family: list[FamilyResult]
