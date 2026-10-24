"""Structural and instruction-hierarchy detectors.

The pattern detector looks at words; these two look at shape. ``StructuralDetector``
finds spoofed role markers, prompt delimiters, injected tool calls and
exfiltration sinks (external URLs, markdown images). ``InstructionHierarchyDetector``
finds claims that a user message outranks the system prompt, which is the core
move behind hierarchy spoofing and authority impersonation.
"""

from __future__ import annotations

import re

from veritas.detectors.base import DetectionResult, Signal, result
from veritas.detectors.normalize import normalize

_ROLE_TAG = re.compile(r"<\s*(system|developer|assistant)\s*>|\[\s*(system|developer)\s*\]",
                       re.IGNORECASE)
_JSON_ROLE = re.compile(r'"role"\s*:\s*"(system|developer)"', re.IGNORECASE)
_DELIMITER = re.compile(
    r"(={2,}\s*(end|start) of (system )?prompt\s*={0,}|-{3,}|###)", re.IGNORECASE)
_TOOL_CALL = re.compile(r"(call the \w+ tool|use your (shell|browser|email) tool|send_email|run `)",
                        re.IGNORECASE)
_MARKDOWN_IMG = re.compile(r"!\[[^\]]*\]\(https?://[^)]+\)")
_EXTERNAL_URL = re.compile(r"https?://[^\s)]+")
_SINK_HINT = re.compile(r"(attacker|collect|exfil|webhook|evil|\?c=|\?data=)", re.IGNORECASE)


class StructuralDetector:
    """Detect spoofed structure and exfiltration sinks."""

    name = "structural"

    def scan(self, text: str, *, canary: str | None = None) -> DetectionResult:
        """Report spoofed roles, delimiters, tool calls and external sinks."""
        _ = canary
        signals: list[Signal] = []
        if _ROLE_TAG.search(text) or _JSON_ROLE.search(text):
            signals.append(Signal(self.name, "prompt_injection", 0.85,
                                  "contains a spoofed system or developer role marker"))
        if _DELIMITER.search(text) and _looks_like_boundary_spoof(text):
            signals.append(Signal(self.name, "prompt_injection", 0.6,
                                  "uses a fake prompt boundary delimiter"))
        if _TOOL_CALL.search(text):
            signals.append(Signal(self.name, "data_exfiltration", 0.8,
                                  "injects a tool or shell invocation"))
        signals.extend(self._sink_signals(text))
        return result(self.name, signals)

    def _sink_signals(self, text: str) -> list[Signal]:
        found: list[Signal] = []
        if _MARKDOWN_IMG.search(text) and _EXTERNAL_URL.search(text):
            found.append(Signal(self.name, "data_exfiltration", 0.8,
                                 "markdown image to an external URL (exfiltration sink)"))
        if _EXTERNAL_URL.search(text) and _SINK_HINT.search(text):
            found.append(Signal(self.name, "data_exfiltration", 0.75,
                                 "external URL with a data-collection parameter"))
        return found


def _looks_like_boundary_spoof(text: str) -> bool:
    """A delimiter alone is benign; pair it with an override cue to reduce noise."""
    low = normalize(text)
    return any(cue in low for cue in ("system prompt", "admin", "override", "new instruction"))


_HIERARCHY_RULES: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"(overrides?|supersedes?|outrank).{0,20}(system|prompt|instructions)"),
     0.9, "claims to override the system instructions"),
    (re.compile(r"(highest|higher|top) priority"), 0.7,
     "asserts a higher priority than the system"),
    (re.compile(r"(this|the following) (message|instruction).{0,20}(priority|supersede)"),
     0.75, "declares itself higher priority"),
    (re.compile(r"(priority override|priority:\s*override)"), 0.8, "explicit priority override"),
    (re.compile(r"(you are|user is) (now )?(admin|root|an administrator)"),
     0.75, "elevates the user to an administrator role"),
    (re.compile(r"authori[sz]ation granted|sanctioned test"), 0.6,
     "fake authorisation to drop the rules"),
]


class InstructionHierarchyDetector:
    """Detect attempts to claim precedence over the system prompt."""

    name = "hierarchy"

    def scan(self, text: str, *, canary: str | None = None) -> DetectionResult:
        """Report hierarchy-override claims found in the normalised text."""
        _ = canary
        low = normalize(text)
        signals = [
            Signal(self.name, "prompt_injection", score, explanation)
            for pattern, score, explanation in _HIERARCHY_RULES
            if pattern.search(low)
        ]
        return result(self.name, signals)
