"""Output scanners: detect leaks, secrets and PII in a model's response.

Input detectors reduce the chance an attack lands; output scanners are the
second line of defence that catches a leak the input filter missed. The canary
scanner needs the per-run token and is the only detector that does, which is why
``scan`` takes an optional ``canary``. The secret and PII scanners use
conservative, well-known patterns so their false-positive rate stays measurable.
"""

from __future__ import annotations

import re

from veritas.detectors.base import DetectionResult, Signal, result

_SECRET_RULES: list[tuple[re.Pattern[str], str, float, str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "secret", 0.95, "AWS access key id"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "secret", 0.97,
     "private key block"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "secret", 0.9, "API secret key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "secret", 0.9, "GitHub personal access token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "secret", 0.9, "Slack token"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "secret", 0.8, "JSON web token"),
]

_PII_RULES: list[tuple[re.Pattern[str], str, float, str]] = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "pii", 0.6,
     "email address"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "pii", 0.7, "card-like number"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "pii", 0.8, "US social-security-like number"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "pii", 0.5, "IPv4 address"),
    (re.compile(r"\+?\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}"), "pii", 0.5,
     "phone-like number"),
]


class SecretScanner:
    """Detect credentials, private keys and compliance markers in output."""

    name = "secret_scanner"

    def scan(self, text: str, *, canary: str | None = None) -> DetectionResult:
        """Report any secret-like token found in ``text``."""
        _ = canary
        return result(self.name, _apply(self.name, _SECRET_RULES, text))


class PIIScanner:
    """Detect common personally identifiable information in output."""

    name = "pii_scanner"

    def scan(self, text: str, *, canary: str | None = None) -> DetectionResult:
        """Report email, card, SSN, IP and phone-like spans in ``text``."""
        _ = canary
        return result(self.name, _apply(self.name, _PII_RULES, text))


class CanaryScanner:
    """Detect the planted canary token leaking into output."""

    name = "canary_scanner"

    def scan(self, text: str, *, canary: str | None = None) -> DetectionResult:
        """Report a leak when the exact canary token appears in ``text``."""
        if canary and canary in text:
            return result(self.name, [Signal(
                self.name, "data_exfiltration", 1.0,
                "the planted canary token appears in the output", evidence="canary leaked")])
        return result(self.name, [])


def _apply(name: str, rules: list[tuple[re.Pattern[str], str, float, str]],
           text: str) -> list[Signal]:
    signals: list[Signal] = []
    for pattern, category, score, explanation in rules:
        if pattern.search(text):
            signals.append(Signal(name, category, score, explanation))
    return signals
