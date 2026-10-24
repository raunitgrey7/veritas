"""Encoding-smuggling detector.

Encoding attacks hide an instruction so a plain-text filter cannot read it, then
tell the model to decode and obey. This detector looks for three things: a
decode-and-follow instruction next to a real base64 blob, an explicit ROT13
instruction, and residual obfuscation (zero-width characters or mixed-script
homoglyphs) that normalisation had to strip. When a base64 blob decodes to text
that itself trips the pattern detector, that is reported as strong evidence.
"""

from __future__ import annotations

import re

from veritas.detectors.base import DetectionResult, Signal, result
from veritas.detectors.normalize import decode_base64_segments, rot13
from veritas.detectors.patterns import PatternDetector

_DECODE_VERB = re.compile(
    r"(decode|base64|b64|cipher|ciphered|encoded|rot13|rot-13)", re.IGNORECASE)
_ZERO_WIDTH_CHARS = set("​‌‍﻿⁠")
_HOMOGLYPH_CHARS = set("аеосрхуі")


class EncodingDetector:
    """Detect smuggled instructions behind encodings and obfuscation."""

    name = "encoding"

    def __init__(self) -> None:
        self._patterns = PatternDetector()

    def scan(self, text: str, *, canary: str | None = None) -> DetectionResult:
        """Report base64/ROT13 smuggling and residual character obfuscation."""
        _ = canary
        signals: list[Signal] = []
        signals.extend(self._base64_signals(text))
        signals.extend(self._rot13_signals(text))
        signals.extend(self._obfuscation_signals(text))
        return result(self.name, signals)

    def _base64_signals(self, text: str) -> list[Signal]:
        decoded = decode_base64_segments(text)
        if not decoded:
            return []
        has_verb = bool(_DECODE_VERB.search(text))
        hostile = any(self._patterns.scan(seg).flagged for seg in decoded)
        if hostile:
            return [Signal(self.name, "prompt_injection", 0.9,
                           "base64 payload decodes to an injection instruction")]
        if has_verb:
            return [Signal(self.name, "prompt_injection", 0.7,
                           "decode-and-follow instruction next to a base64 blob")]
        return []

    def _rot13_signals(self, text: str) -> list[Signal]:
        if not re.search(r"rot[-\s]?13", text, re.IGNORECASE):
            return []
        if self._patterns.scan(rot13(text)).flagged:
            return [Signal(self.name, "prompt_injection", 0.85,
                           "ROT13 content decodes to an injection instruction")]
        return [Signal(self.name, "prompt_injection", 0.6,
                       "explicit ROT13 decode-and-follow instruction")]

    def _obfuscation_signals(self, text: str) -> list[Signal]:
        found: list[Signal] = []
        if _ZERO_WIDTH_CHARS.intersection(text):
            found.append(Signal(self.name, "prompt_injection", 0.6,
                                 "contains zero-width characters splitting words"))
        if _HOMOGLYPH_CHARS.intersection(text):
            found.append(Signal(self.name, "prompt_injection", 0.6,
                                 "mixes look-alike non-Latin letters into Latin text"))
        return found
