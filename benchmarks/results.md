# veritas benchmark results

Seed: 1337. veritas 0.1.0.
Corpus: 478 attacks across 16 families, 430 benign (30 hard negatives).

## Guardrail detector quality (input classifier on the full corpus)

| precision | recall | f1 | false-positive rate | hard-negative fp rate |
| --- | --- | --- | --- | --- |
| 0.9933 | 0.9247 | 0.9577 | 0.007 | 0.1 |

## Attack success rate by model (lower is safer)

| model | cases | ASR | 95% CI | refusal rate | mean latency (ms) |
| --- | --- | --- | --- | --- | --- |
| echo | 478 | 0.6318 | [0.5879, 0.6757] | 0.0 | 0.001 |
| mock_vulnerable | 478 | 0.8766 | [0.8473, 0.9059] | 0.0 | 0.0161 |
| mock_half | 478 | 0.4121 | [0.3703, 0.454] | 0.546 | 0.0079 |
| mock_refusing | 478 | 0.0 | [0.0, 0.0] | 1.0 | 0.001 |
| guarded_vulnerable | 478 | 0.0314 | [0.0167, 0.0481] | 0.9477 | 0.0693 |

## Guardrail effect

The guardrail lowers the vulnerable model's attack success rate from 0.8766 to 0.0314, a relative reduction of 0.9642.
