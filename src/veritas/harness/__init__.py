"""Target harness: pluggable models, a deterministic judge, and metrics.

``runner.run_model`` replays the attack corpus against a model and returns
per-case records; ``metrics.summarise_model`` turns those into attack-success
rates with bootstrap intervals. Models live in ``models``; the judge rubric in
``judge``; shared value types in ``types``.
"""

from veritas.harness.judge import is_refusal, judge, resolve_marker
from veritas.harness.metrics import (
    DetectorMetrics,
    bootstrap_interval,
    detector_metrics,
    summarise_model,
)
from veritas.harness.models import (
    AnthropicModel,
    EchoModel,
    GuardedModel,
    MockModel,
    ModelUnderTest,
)
from veritas.harness.runner import build_system_prompt, make_canary, run_model
from veritas.harness.types import (
    EvalRecord,
    FamilyResult,
    Interval,
    Judgement,
    ModelResponse,
    ModelResult,
    Turn,
)

__all__ = [
    "AnthropicModel",
    "DetectorMetrics",
    "EchoModel",
    "EvalRecord",
    "FamilyResult",
    "GuardedModel",
    "Interval",
    "Judgement",
    "MockModel",
    "ModelResponse",
    "ModelResult",
    "ModelUnderTest",
    "Turn",
    "bootstrap_interval",
    "build_system_prompt",
    "detector_metrics",
    "is_refusal",
    "judge",
    "make_canary",
    "resolve_marker",
    "run_model",
    "summarise_model",
]
