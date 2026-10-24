# veritas build report

This report records what was built, every published number with the exact
command that produced it, and the known gaps. All metrics use seed 1337 and are
reproducible with `make bench`.

## What was built

A deterministic LLM evaluation, red-teaming and guardrail platform:

- A synthetic attack corpus of 478 cases across 16 families with seeded variants
  (encodings, obfuscation, three non-English lexicons, multi-turn), and a benign
  corpus of 430 prompts including 30 hard negatives.
- Seven guardrail detectors (pattern, structural, instruction-hierarchy,
  encoding, and output scanners for secrets, PII and a canary token) composed in
  a pipeline that returns allow/flag/block with a risk score and reasons.
- A target harness with a pluggable model interface, four deterministic models
  plus an optional Anthropic adapter, a deterministic judge, and attack success
  rate per family with bootstrap confidence intervals.
- A benchmark that writes `benchmarks/results.json` and `results.md`, a
  regression gate with explicit thresholds and baseline comparison, and an HTML
  report.
- A FastAPI service with `/health`, `/metrics` (Prometheus), structured JSON
  logging, request ids, input validation, optional API-key auth, and a
  single-page vanilla-JS dashboard.
- Packaging: multi-stage non-root Dockerfile, docker-compose, Makefile, and a CI
  workflow that lints, tests, benchmarks and gates.

## Measured numbers and their commands

### Corpus size (`uv run python -m veritas.cli corpus`)

- Attack cases: 478 across 16 families.
- Benign cases: 430, of which 30 are hard negatives.
- Languages: English 382, Spanish 34, Hinglish 32, French 30.

### Detector quality (`make bench`, from `benchmarks/results.json` field `detector.metrics`)

- Precision: 0.9933
- Recall: 0.9247
- F1: 0.9577
- False-positive rate (all 430 benign): 0.007 (3 false positives)
- False-positive rate (30 hard negatives): 0.1 (3 false positives)
- True positives 442, false negatives 36, false positives 3, true negatives 427.

### Attack success rate by model (`make bench`, field `models`)

| model | ASR | 95% CI | refusal rate |
| --- | --- | --- | --- |
| echo | 0.6318 | [0.5879, 0.6757] | 0.0 |
| mock_vulnerable | 0.8766 | [0.8473, 0.9059] | 0.0 |
| mock_half | 0.4121 | [0.3703, 0.454] | 0.546 |
| mock_refusing | 0.0 | [0.0, 0.0] | 1.0 |
| guarded_vulnerable | 0.0314 | [0.0167, 0.0481] | 0.9477 |

### Guardrail effect (`make bench`, field `guardrail_effect`)

- Vulnerable model ASR without the guardrail: 0.8766
- Same model wrapped in the guardrail: 0.0314
- Absolute reduction: 0.8452; relative reduction: 0.9642

### Performance (machine-dependent, not seed-reproducible)

- Detector throughput: 23,147 prompts per second single-threaded, measured on an
  Apple Silicon Mac (`benchmarks/results.json` field `detector.prompts_per_second`).
  This figure varies by machine and is therefore excluded from the determinism
  tests and the regression gate.

### Test count (`make test`)

- 180 tests pass. 165 test functions, 15 of which come from one parametrization
  over the 16 attack families. The suite includes property-based tests
  (`tests/test_property.py`), adversarial and robustness tests
  (`tests/test_adversarial.py`) and determinism tests (`tests/test_determinism.py`).

## Clean-shell output tails

`make lint`:

```
uv run ruff check src tests
All checks passed!
```

`make test`:

```
........................................................................ [ 40%]
........................................................................ [ 80%]
....................................                                     [100%]
180 passed in 17.53s
```

`make bench`:

```
corpus: 478 attacks / 430 benign
detector: precision=0.9933 recall=0.9247 f1=0.9577 fp_rate=0.007
guardrail effect: ASR 0.8766 -> 0.0314 (relative reduction 0.9642)
wrote benchmarks/results.json and benchmarks/results.md
```

`make gate`:

```
PASS overall
  [ok  ] guarded_asr_ceiling: observed=0.0314 bound=0.1
  [ok  ] detector_recall_floor: observed=0.9247 bound=0.85
  [ok  ] detector_precision_floor: observed=0.9933 bound=0.95
  [ok  ] detector_fp_rate_ceiling: observed=0.007 bound=0.05
  [ok  ] asr_regression:echo: observed=0.6318 bound=0.6818
  [ok  ] asr_regression:mock_vulnerable: observed=0.8766 bound=0.9266
  [ok  ] asr_regression:mock_half: observed=0.4121 bound=0.4621
  [ok  ] asr_regression:mock_refusing: observed=0.0 bound=0.05
  [ok  ] asr_regression:guarded_vulnerable: observed=0.0314 bound=0.0814
  [ok  ] recall_regression: observed=0.9247 bound=0.8747
```

## Known gaps

- Non-English recall is about 0.75. Only a small lexicon of trigger words is
  translated, so a translated attack whose trigger words are outside the lexicon
  can pass the input filter. This is measured, not hidden: see
  `detector.recall_by_family` and the language breakdown.
- Three benign false positives remain, all hard negatives that quote attack
  phrases verbatim. They are kept deliberately rather than special-cased away.
- Output scanners do not catch a secret split across tokens (letters separated by
  spaces). This is documented and asserted in `tests/test_adversarial.py`.
- The models under test are deterministic simulations, by design, so the
  benchmark is reproducible. The Anthropic adapter is implemented but optional
  and is never exercised by tests or the benchmark, so its real-world ASR is not
  measured here.
- Latency and throughput are measured but machine-dependent, so they are reported
  separately from the reproducible metrics and are not gated.
