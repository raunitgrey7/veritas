"""Command line interface for veritas.

Subcommands cover the whole workflow: ``scan`` a single prompt through the
guardrail, build the ``corpus``, run the ``bench`` and the regression ``gate``,
render an HTML ``report``, and ``serve`` the API. Each subcommand is a thin
wrapper around the library so the behaviour is identical to calling the API or
the benchmark module directly.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from veritas import DEFAULT_SEED, __version__
from veritas import benchmark as benchmark_module
from veritas import gate as gate_module
from veritas import report as report_module
from veritas.corpus import build_attack_corpus, build_benign_corpus, coverage, save_jsonl
from veritas.detectors import Guardrail


def _cmd_scan(args: argparse.Namespace) -> int:
    guard = Guardrail()
    verdict = guard.evaluate_input(args.prompt, canary=args.canary)
    payload = {
        "verdict": verdict.verdict.value,
        "risk": round(verdict.risk, 4),
        "categories": verdict.categories,
        "reasons": verdict.reasons,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"verdict: {payload['verdict']}  risk: {payload['risk']}")
        for reason in payload["reasons"]:
            print(f"  - {reason}")
    return 0


def _cmd_corpus(args: argparse.Namespace) -> int:
    attacks = build_attack_corpus(args.seed)
    benign = build_benign_corpus(args.seed)
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    save_jsonl(attacks, out / "attacks.jsonl")
    save_jsonl(benign, out / "benign.jsonl")
    print(json.dumps(coverage(attacks, benign), indent=2))
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("veritas.api.app:app", host=args.host, port=args.port, log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser with all subcommands."""
    parser = argparse.ArgumentParser(prog="veritas", description=__doc__)
    parser.add_argument("--version", action="version", version=f"veritas {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a single prompt through the guardrail")
    scan.add_argument("prompt")
    scan.add_argument("--canary", default=None)
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=_cmd_scan)

    corpus = sub.add_parser("corpus", help="build the corpus and print coverage")
    corpus.add_argument("--seed", type=int, default=DEFAULT_SEED)
    corpus.add_argument("--out", type=Path, default=Path("data"))
    corpus.set_defaults(func=_cmd_corpus)

    bench = sub.add_parser("bench", help="run the benchmark")
    bench.add_argument("--seed", type=int, default=DEFAULT_SEED)
    bench.add_argument("--out", type=Path, default=benchmark_module.BENCH_DIR)
    bench.set_defaults(func=lambda a: benchmark_module.main(["--seed", str(a.seed),
                                                             "--out", str(a.out)]))

    gate = sub.add_parser("gate", help="run the regression gate")
    gate.add_argument("--current", type=Path, default=Path("benchmarks/results.json"))
    gate.add_argument("--baseline", type=Path, default=Path("benchmarks/baseline.json"))
    gate.set_defaults(func=lambda a: gate_module.main(["--current", str(a.current),
                                                       "--baseline", str(a.baseline)]))

    report = sub.add_parser("report", help="render the HTML report")
    report.add_argument("--current", type=Path, default=Path("benchmarks/results.json"))
    report.add_argument("--out", type=Path, default=Path("benchmarks/report.html"))
    report.set_defaults(func=lambda a: report_module.main(["--current", str(a.current),
                                                           "--out", str(a.out)]))

    serve = sub.add_parser("serve", help="serve the API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=_cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the chosen subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
