"""Benchmark harness: build data, evaluate, and write reproducible results.

Run with ``uv run python -m veritas.benchmark`` (or ``make bench``). The harness
is deterministic: given the seed it regenerates the corpus, measures detector
quality on it, runs a fixed roster of models, and writes ``benchmarks/results.json``
plus a Markdown table. Every number in the README is produced here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from veritas import DEFAULT_SEED, __version__
from veritas.corpus import (
    AttackCase,
    BenignCase,
    build_attack_corpus,
    build_benign_corpus,
    coverage,
    save_jsonl,
)
from veritas.detectors import Guardrail
from veritas.harness import (
    EchoModel,
    GuardedModel,
    MockModel,
    ModelUnderTest,
    detector_metrics,
    run_model,
    summarise_model,
)

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
BENCH_DIR = ROOT / "benchmarks"


def _model_roster(guardrail: Guardrail) -> list[ModelUnderTest]:
    """The fixed set of models the benchmark reports on."""
    return [
        EchoModel(name="echo"),
        MockModel(compliance=1.0, name="mock_vulnerable"),
        MockModel(compliance=0.5, seed=DEFAULT_SEED, name="mock_half"),
        MockModel(compliance=0.0, name="mock_refusing"),
        GuardedModel(inner=MockModel(compliance=1.0, name="inner"),
                     guardrail=guardrail, name="guarded_vulnerable"),
    ]


def _corpus_digest(attacks: list[AttackCase], benign: list[BenignCase]) -> str:
    hasher = hashlib.sha256()
    for case in attacks:
        hasher.update(case.model_dump_json().encode())
    for case in benign:
        hasher.update(case.model_dump_json().encode())
    return hasher.hexdigest()


def _detector_section(guardrail: Guardrail, attacks: list[AttackCase],
                      benign: list[BenignCase]) -> dict[str, Any]:
    """Measure precision, recall, false positives, per-family recall and latency."""
    attack_flags = [guardrail.evaluate_input(c.full_text).flagged for c in attacks]
    benign_flags = [guardrail.evaluate_input(b.text).flagged for b in benign]
    hard_flags = [f for f, b in zip(benign_flags, benign, strict=True) if b.hard_negative]
    metrics = detector_metrics(attack_flags, benign_flags, hard_flags)
    by_family: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for case, flagged in zip(attacks, attack_flags, strict=True):
        by_family[case.family.value][0] += int(flagged)
        by_family[case.family.value][1] += 1
    recall_by_family = {k: round(v[0] / v[1], 4) for k, v in sorted(by_family.items())}
    latency = _detector_latency(guardrail, attacks, benign)
    return {
        "metrics": metrics.model_dump(),
        "recall_by_family": recall_by_family,
        "prompts_per_second": latency,
    }


def _detector_latency(guardrail: Guardrail, attacks: list[AttackCase],
                      benign: list[BenignCase]) -> float:
    prompts = [c.full_text for c in attacks] + [b.text for b in benign]
    start = time.perf_counter()
    for text in prompts:
        guardrail.evaluate_input(text)
    elapsed = time.perf_counter() - start
    return round(len(prompts) / elapsed, 1) if elapsed else 0.0


def _models_section(guardrail: Guardrail, attacks: list[AttackCase],
                    seed: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run every model and return per-model summaries and the guardrail effect."""
    summaries: list[dict[str, Any]] = []
    asr_by_name: dict[str, float] = {}
    for model in _model_roster(guardrail):
        records = run_model(model, attacks, seed=seed, guardrail=guardrail)
        summary = summarise_model(model.name, records, seed=seed)
        summaries.append(summary.model_dump())
        asr_by_name[model.name] = summary.attack_success_rate.estimate
    unguarded = asr_by_name["mock_vulnerable"]
    guarded = asr_by_name["guarded_vulnerable"]
    effect = {
        "unguarded_model": "mock_vulnerable",
        "guarded_model": "guarded_vulnerable",
        "unguarded_asr": unguarded,
        "guarded_asr": guarded,
        "absolute_reduction": round(unguarded - guarded, 4),
        "relative_reduction": round((unguarded - guarded) / unguarded, 4) if unguarded else 0.0,
    }
    return summaries, effect


def run_benchmark(seed: int = DEFAULT_SEED) -> dict[str, Any]:
    """Build data, evaluate detectors and models, and return the result document."""
    attacks = build_attack_corpus(seed)
    benign = build_benign_corpus(seed)
    DATA_DIR.mkdir(exist_ok=True)
    save_jsonl(attacks, DATA_DIR / "attacks.jsonl")
    save_jsonl(benign, DATA_DIR / "benign.jsonl")
    guardrail = Guardrail()
    models, effect = _models_section(guardrail, attacks, seed)
    return {
        "veritas_version": __version__,
        "seed": seed,
        "corpus": {**coverage(attacks, benign), "sha256": _corpus_digest(attacks, benign)},
        "detector": _detector_section(guardrail, attacks, benign),
        "models": models,
        "guardrail_effect": effect,
    }


def _markdown_table(result: dict[str, Any]) -> str:
    det = result["detector"]["metrics"]
    lines = [
        "# veritas benchmark results",
        "",
        f"Seed: {result['seed']}. veritas {result['veritas_version']}.",
        f"Corpus: {result['corpus']['attack_total']} attacks across "
        f"{result['corpus']['families']} families, {result['corpus']['benign_total']} "
        f"benign ({result['corpus']['benign_hard_negatives']} hard negatives).",
        "",
        "## Guardrail detector quality (input classifier on the full corpus)",
        "",
        "| precision | recall | f1 | false-positive rate | hard-negative fp rate |",
        "| --- | --- | --- | --- | --- |",
        f"| {det['precision']} | {det['recall']} | {det['f1']} | "
        f"{det['false_positive_rate']} | {det['hard_negative_fp_rate']} |",
        "",
        "## Attack success rate by model (lower is safer)",
        "",
        "| model | cases | ASR | 95% CI | refusal rate | mean latency (ms) |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for m in result["models"]:
        asr = m["attack_success_rate"]
        lines.append(
            f"| {m['model']} | {m['n_cases']} | {asr['estimate']} | "
            f"[{asr['low']}, {asr['high']}] | {m['refusal_rate']} | {m['mean_latency_ms']} |")
    effect = result["guardrail_effect"]
    lines += [
        "",
        "## Guardrail effect",
        "",
        f"The guardrail lowers the vulnerable model's attack success rate from "
        f"{effect['unguarded_asr']} to {effect['guarded_asr']}, a relative reduction of "
        f"{effect['relative_reduction']}.",
        "",
    ]
    return "\n".join(lines)


def write_outputs(result: dict[str, Any], out_dir: Path = BENCH_DIR) -> None:
    """Write ``results.json`` and ``results.md`` into ``out_dir``."""
    out_dir.mkdir(exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (out_dir / "results.md").write_text(_markdown_table(result), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``python -m veritas.benchmark``."""
    parser = argparse.ArgumentParser(description="Run the veritas benchmark.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=BENCH_DIR)
    args = parser.parse_args(argv)
    result = run_benchmark(args.seed)
    write_outputs(result, args.out)
    det = result["detector"]["metrics"]
    effect = result["guardrail_effect"]
    print(f"corpus: {result['corpus']['attack_total']} attacks / "
          f"{result['corpus']['benign_total']} benign")
    print(f"detector: precision={det['precision']} recall={det['recall']} f1={det['f1']} "
          f"fp_rate={det['false_positive_rate']}")
    print(f"guardrail effect: ASR {effect['unguarded_asr']} -> {effect['guarded_asr']} "
          f"(relative reduction {effect['relative_reduction']})")
    print(f"wrote {args.out / 'results.json'} and {args.out / 'results.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
