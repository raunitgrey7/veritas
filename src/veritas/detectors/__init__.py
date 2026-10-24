"""Deterministic guardrail detectors and the pipeline that composes them.

Input detectors (``pattern``, ``structural``, ``hierarchy``, ``encoding``) score
an incoming prompt. Output scanners (``secret_scanner``, ``pii_scanner``,
``canary_scanner``) score a model response. :class:`Guardrail` runs a suite and
returns a :class:`GuardVerdict` with a risk score and reasons.
"""

from veritas.detectors.base import DetectionResult, Detector, Signal, Verdict
from veritas.detectors.encoding import EncodingDetector
from veritas.detectors.output_scanners import CanaryScanner, PIIScanner, SecretScanner
from veritas.detectors.patterns import PatternDetector
from veritas.detectors.pipeline import (
    BLOCK_THRESHOLD,
    FLAG_THRESHOLD,
    Guardrail,
    GuardVerdict,
    input_detectors,
    output_detectors,
)
from veritas.detectors.structural import InstructionHierarchyDetector, StructuralDetector

__all__ = [
    "BLOCK_THRESHOLD",
    "FLAG_THRESHOLD",
    "CanaryScanner",
    "DetectionResult",
    "Detector",
    "EncodingDetector",
    "GuardVerdict",
    "Guardrail",
    "InstructionHierarchyDetector",
    "PIIScanner",
    "PatternDetector",
    "SecretScanner",
    "Signal",
    "StructuralDetector",
    "Verdict",
    "input_detectors",
    "output_detectors",
]
