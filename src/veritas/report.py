"""Generate a self-contained HTML report from a benchmark result.

The report is a single static HTML file with inline CSS and no external assets,
so it opens offline and can be attached to a CI run. It restates the measured
numbers from ``results.json`` as tables; it computes nothing new, so the report
can never disagree with the JSON it was built from.
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

_STYLE = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto;
       max-width: 70rem; color: #1a1a1a; line-height: 1.5; padding: 0 1rem; }
h1 { border-bottom: 2px solid #333; padding-bottom: .3rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; }
th { background: #f2f2f2; }
.good { color: #0a7d2c; font-weight: 600; }
.bad { color: #b00020; font-weight: 600; }
.meta { color: #555; font-size: .9rem; }
caption { text-align: left; font-weight: 600; margin-bottom: .3rem; }
"""


def _cell(value: Any) -> str:
    return html.escape(str(value))


def _detector_table(result: dict[str, Any]) -> str:
    det = result["detector"]["metrics"]
    rows = "".join(
        f"<tr><td>{_cell(k)}</td><td>{_cell(v)}</td></tr>" for k, v in det.items())
    return f"<table><caption>Detector quality</caption>{rows}</table>"


def _models_table(result: dict[str, Any]) -> str:
    head = ("<tr><th>model</th><th>cases</th><th>ASR</th><th>95% CI</th>"
            "<th>refusal rate</th><th>mean latency (ms)</th></tr>")
    rows = []
    for m in result["models"]:
        asr = m["attack_success_rate"]
        rows.append(
            f"<tr><td>{_cell(m['model'])}</td><td>{_cell(m['n_cases'])}</td>"
            f"<td>{_cell(asr['estimate'])}</td>"
            f"<td>[{_cell(asr['low'])}, {_cell(asr['high'])}]</td>"
            f"<td>{_cell(m['refusal_rate'])}</td><td>{_cell(m['mean_latency_ms'])}</td></tr>")
    return (f"<table><caption>Attack success rate by model</caption>{head}"
            f"{''.join(rows)}</table>")


def _family_table(result: dict[str, Any]) -> str:
    recall = result["detector"]["recall_by_family"]
    head = "<tr><th>family</th><th>detector recall</th></tr>"
    rows = "".join(f"<tr><td>{_cell(k)}</td><td>{_cell(v)}</td></tr>"
                   for k, v in recall.items())
    return f"<table><caption>Detector recall by attack family</caption>{head}{rows}</table>"


def render_report(result: dict[str, Any]) -> str:
    """Return the full HTML document for a benchmark result."""
    corpus = result["corpus"]
    effect = result["guardrail_effect"]
    reduction = effect["relative_reduction"]
    summary = (f"Guardrail reduces attack success rate from {effect['unguarded_asr']} to "
               f"{effect['guarded_asr']} (relative reduction "
               f"<span class='good'>{reduction}</span>).")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>veritas benchmark report</title><style>{_STYLE}</style></head>
<body>
<h1>veritas benchmark report</h1>
<p class="meta">veritas {_cell(result['veritas_version'])}, seed {_cell(result['seed'])}.
Corpus: {_cell(corpus['attack_total'])} attacks across {_cell(corpus['families'])} families,
{_cell(corpus['benign_total'])} benign ({_cell(corpus['benign_hard_negatives'])} hard negatives).
Corpus sha256 {_cell(corpus['sha256'][:16])}.</p>
<p>{summary}</p>
{_detector_table(result)}
{_models_table(result)}
{_family_table(result)}
</body></html>
"""


def main(argv: list[str] | None = None) -> int:
    """CLI entry point to render an HTML report from a results file."""
    parser = argparse.ArgumentParser(description="Render the veritas HTML report.")
    parser.add_argument("--current", type=Path, default=Path("benchmarks/results.json"))
    parser.add_argument("--out", type=Path, default=Path("benchmarks/report.html"))
    args = parser.parse_args(argv)
    result = json.loads(args.current.read_text(encoding="utf-8"))
    args.out.write_text(render_report(result), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
