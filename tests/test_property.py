"""Property-based tests with Hypothesis.

These assert invariants that must hold for any input, not just the corpus:
normalisation never crashes and is idempotent, verdicts are well-formed, scores
stay in range, and benign scanners never raise. Property tests catch the edge
cases enumerated examples miss.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from veritas.detectors import Guardrail
from veritas.detectors.base import Verdict
from veritas.detectors.normalize import normalize, strip_zero_width
from veritas.harness import bootstrap_interval

_guard = Guardrail()
text = st.text(max_size=400)


@given(text)
def test_normalize_never_raises(s: str):
    normalize(s)


@given(text)
def test_normalize_is_idempotent(s: str):
    assert normalize(normalize(s)) == normalize(s)


@given(text)
def test_normalize_is_lowercase(s: str):
    assert normalize(s) == normalize(s).lower()


@given(text)
def test_strip_zero_width_removes_all_zero_width(s: str):
    stripped = strip_zero_width(s)
    assert not any(ch in stripped for ch in "​‌‍﻿⁠")


@given(text)
def test_input_verdict_is_well_formed(s: str):
    v = _guard.evaluate_input(s)
    assert isinstance(v.verdict, Verdict)
    assert 0.0 <= v.risk <= 1.0


@given(text)
def test_signal_scores_in_range(s: str):
    v = _guard.evaluate_input(s)
    assert all(0.0 <= sig.score <= 1.0 for sig in v.signals)


@given(text)
def test_output_scanner_never_raises(s: str):
    _guard.evaluate_output(s, canary="CNRY-test")


@given(text)
def test_flagged_implies_nonzero_risk(s: str):
    v = _guard.evaluate_input(s)
    assert (not v.flagged) or v.risk > 0.0


@given(st.lists(st.booleans(), min_size=1, max_size=200), st.integers(min_value=0, max_value=1000))
def test_bootstrap_interval_contains_estimate(outcomes: list[bool], seed: int):
    interval = bootstrap_interval(outcomes, seed=seed, resamples=200)
    assert interval.low <= interval.estimate <= interval.high
    assert 0.0 <= interval.estimate <= 1.0


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", max_size=100))
def test_plain_lowercase_text_rarely_blocks(s: str):
    # A sanity bound: arbitrary lowercase letters should not reach BLOCK unless
    # they spell a trigger phrase. We only assert the verdict is valid.
    v = _guard.evaluate_input(s)
    assert v.verdict in set(Verdict)
