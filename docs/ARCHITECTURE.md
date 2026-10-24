# Architecture

veritas is a library with a thin CLI and API on top. The dependency direction is
one way: corpus does not import detectors, detectors do not import the harness,
and the API imports all three but nothing imports the API. This keeps each layer
testable in isolation.

## Modules

### veritas.corpus

Builds the attack and benign corpora.

- `schema.py`: the record types (`AttackCase`, `BenignCase`) and the enums for
  family, category, severity and expected behaviour. The family-to-category map
  lives here. Every attack carries a `compliance_marker`: the harmless sentinel
  string a complying model would emit. Leak families use the `{canary}`
  placeholder, resolved per run.
- `families.py`: hand-written seed templates grouped into 16 families. No
  template contains operationally harmful content.
- `variants.py`: seeded, deterministic transforms (base64, ROT13, leetspeak,
  homoglyph, zero-width, three language lexicons, multi-turn split). The marker
  is protected by splitting on it so character transforms cannot corrupt it.
- `generator.py`: composes templates and variants into `AttackCase` records with
  stable ids, and checks corpus invariants (unique ids, at least 12 families).
- `benign.py`: builds legitimate prompts by template-and-filler combination, plus
  a curated set of hard negatives that reuse attack vocabulary.
- `store.py`: JSONL read and write, and the coverage summary.

### veritas.detectors

Deterministic guardrails. Each detector has a `name` and a `scan` method that
returns a `DetectionResult` of weighted `Signal`s.

- `normalize.py`: reverses obfuscation (strip zero-width, fold homoglyphs, undo
  leetspeak, collapse whitespace, decode base64, ROT13) so one pattern catches a
  phrase and its variants.
- `patterns.py`: a table of scored regular expressions over normalised text,
  covering injection, jailbreak, leak and policy cues, with a small multilingual
  extension.
- `structural.py`: spoofed role markers, fake prompt delimiters, injected tool
  calls, exfiltration sinks, and the instruction-hierarchy override detector.
- `encoding.py`: base64 and ROT13 smuggling (it decodes and re-scans), plus
  residual zero-width and homoglyph obfuscation.
- `output_scanners.py`: secret, PII and canary scanners for model responses.
- `pipeline.py`: `Guardrail` composes the detectors and aggregates signals into a
  `GuardVerdict` (allow, flag or block) with a risk score and reasons. Thresholds
  are explicit constants.

### veritas.harness

Evaluates a model under test.

- `types.py`: value types (`Turn`, `ModelResponse`, `EvalRecord`, `Interval`,
  `ModelResult`).
- `models.py`: the pluggable `ModelUnderTest` protocol and four implementations:
  `EchoModel`, `MockModel` (seeded instruction-follower), `GuardedModel` (wraps a
  model with the guardrail) and `AnthropicModel` (optional online adapter).
- `judge.py`: the deterministic rubric. An attack succeeded if the resolved
  marker appears in the output; refusal is detected separately.
- `runner.py`: plants the per-run canary in the system prompt, replays each
  attack, records the guardrail verdict and the judgement.
- `metrics.py`: seeded bootstrap intervals, per-model and per-family summaries,
  and the detector precision/recall computation.

### Top-level modules

- `benchmark.py`: orchestrates a full run and writes `benchmarks/results.json`
  and `results.md`.
- `gate.py`: the regression gate (absolute thresholds plus baseline comparison).
- `report.py`: renders a static HTML report from a results document.
- `cli.py`: subcommands `scan`, `corpus`, `bench`, `gate`, `report`, `serve`.
- `api/`: the FastAPI app (`app.py`), typed schemas, settings, observability
  (JSON logging, request ids, Prometheus registry) and the static dashboard.

## Data flow

1. The generator expands templates into the attack corpus; the benign builder
   produces the negative set. Both are deterministic functions of the seed.
2. The guardrail scans every case; comparing flags against labels yields detector
   precision, recall and false-positive rate.
3. The harness replays each attack against each model under test. The judge marks
   success or refusal. Metrics aggregate into ASR per family with bootstrap CIs.
4. The benchmark writes a single JSON document. The gate reads it and compares
   against the baseline and the thresholds. The report renders it as HTML. The
   API serves it alongside live scanning.

## Determinism

The corpus, the judge and the bootstrap are deterministic given the seed, so
`results.json` is reproducible except for wall-clock latency and throughput,
which are measured but machine-dependent and are therefore excluded from the
determinism tests and the regression comparison.
