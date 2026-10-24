"""Tests for the benchmark, the regression gate and the HTML report."""

from __future__ import annotations

import copy
import json

from veritas.benchmark import run_benchmark, write_outputs
from veritas.gate import (
    DETECTOR_RECALL_MIN,
    GUARDED_ASR_MAX,
    evaluate_gate,
)
from veritas.report import render_report


def test_benchmark_runs_and_has_sections():
    result = run_benchmark()
    assert set(result) >= {"corpus", "detector", "models", "guardrail_effect", "seed"}


def _stable_view(result):
    # Exclude wall-clock latency and throughput, which are machine-dependent.
    det = result["detector"]
    models = {m["model"]: (m["attack_success_rate"], m["refusal_rate"]) for m in result["models"]}
    return det["metrics"], det["recall_by_family"], models, result["corpus"]["sha256"]


def test_benchmark_is_deterministic():
    a = run_benchmark()
    b = run_benchmark()
    assert _stable_view(a) == _stable_view(b)


def test_benchmark_guardrail_reduces_asr():
    effect = run_benchmark()["guardrail_effect"]
    assert effect["guarded_asr"] < effect["unguarded_asr"]


def test_benchmark_detector_meets_floor():
    det = run_benchmark()["detector"]["metrics"]
    assert det["recall"] >= DETECTOR_RECALL_MIN


def test_write_outputs_creates_files(tmp_path):
    result = run_benchmark()
    write_outputs(result, tmp_path)
    assert (tmp_path / "results.json").exists()
    assert (tmp_path / "results.md").exists()
    table = (tmp_path / "results.md").read_text()
    assert "attack success rate" in table.lower()


def test_gate_passes_on_good_result():
    result = run_benchmark()
    report = evaluate_gate(result, baseline=result)
    assert report.passed


def test_gate_fails_when_guarded_asr_too_high():
    result = run_benchmark()
    broken = copy.deepcopy(result)
    for m in broken["models"]:
        if m["model"] == "guarded_vulnerable":
            m["attack_success_rate"]["estimate"] = GUARDED_ASR_MAX + 0.2
    report = evaluate_gate(broken, baseline=None)
    assert not report.passed
    assert any(c.name == "guarded_asr_ceiling" and not c.passed for c in report.checks)


def test_gate_fails_on_asr_regression():
    result = run_benchmark()
    regressed = copy.deepcopy(result)
    for m in regressed["models"]:
        if m["model"] == "mock_half":
            m["attack_success_rate"]["estimate"] = 0.99
    report = evaluate_gate(regressed, baseline=result)
    assert not report.passed
    assert any(c.name.startswith("asr_regression") and not c.passed for c in report.checks)


def test_gate_fails_on_recall_regression():
    result = run_benchmark()
    regressed = copy.deepcopy(result)
    regressed["detector"]["metrics"]["recall"] = 0.1
    report = evaluate_gate(regressed, baseline=result)
    assert not report.passed


def test_gate_render_contains_overall_line():
    result = run_benchmark()
    text = evaluate_gate(result, baseline=result).render()
    assert "overall" in text


def test_report_renders_html():
    result = run_benchmark()
    html = render_report(result)
    assert "<!doctype html>" in html
    assert "veritas benchmark report" in html
    assert str(result["corpus"]["attack_total"]) in html


def test_report_is_valid_json_source():
    result = run_benchmark()
    # round-trips through json without loss, so the report always matches the data
    assert json.loads(json.dumps(result))["seed"] == result["seed"]
