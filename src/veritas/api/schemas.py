"""Typed request and response models for the API.

Keeping the schemas in one place makes the OpenAPI document precise and gives the
dashboard a stable contract. Validation (length limits, required fields) lives
here so malformed input is rejected before it reaches the detectors.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

MAX_PROMPT_CHARS = 20_000


class ScanRequest(BaseModel):
    """A prompt to evaluate with the input guardrail."""

    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)
    canary: str | None = Field(default=None, max_length=256)


class OutputScanRequest(BaseModel):
    """A model output to evaluate with the output scanners."""

    output: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)
    canary: str | None = Field(default=None, max_length=256)


class SignalOut(BaseModel):
    """One detector signal in a response."""

    detector: str
    category: str
    score: float
    explanation: str
    evidence: str = ""


class ScanResponse(BaseModel):
    """The guardrail verdict for a prompt or output."""

    verdict: str
    risk: float
    categories: list[str]
    reasons: list[str]
    signals: list[SignalOut]


class HealthResponse(BaseModel):
    """Liveness and version information."""

    status: str
    service: str
    version: str


class CoverageResponse(BaseModel):
    """Corpus coverage counts for the dashboard."""

    attack_total: int
    benign_total: int
    benign_hard_negatives: int
    families: int
    by_family: dict[str, int]
    by_category: dict[str, int]
    by_severity: dict[str, int]
    by_variant: dict[str, int]
    by_language: dict[str, int]
