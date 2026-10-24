"""Read and write corpora as JSONL and compute coverage statistics.

JSONL keeps each case on its own line so corpora diff cleanly in git and stream
without loading the whole file. Files are cached under ``data/`` by the builder
CLI; nothing here reaches the network.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from pydantic import BaseModel

from veritas.corpus.schema import AttackCase, BenignCase


def save_jsonl(cases: list[BaseModel], path: Path) -> None:
    """Write cases to ``path`` as one compact JSON object per line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [case.model_dump_json() for case in cases]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_jsonl[T: BaseModel](path: Path, model: type[T]) -> list[T]:
    """Load cases of type ``model`` from a JSONL file."""
    text = path.read_text(encoding="utf-8")
    return [model.model_validate_json(line) for line in text.splitlines() if line.strip()]


def coverage(attacks: list[AttackCase], benign: list[BenignCase]) -> dict[str, object]:
    """Summarise the corpus: totals and counts by family, category, variant, language."""
    return {
        "attack_total": len(attacks),
        "benign_total": len(benign),
        "benign_hard_negatives": sum(1 for b in benign if b.hard_negative),
        "families": len({a.family for a in attacks}),
        "by_family": _count(a.family.value for a in attacks),
        "by_category": _count(a.category.value for a in attacks),
        "by_severity": _count(a.severity.value for a in attacks),
        "by_variant": _count(a.variant for a in attacks),
        "by_language": _count(a.language for a in attacks),
        "benign_by_category": _count(b.category for b in benign),
    }


def _count(values: object) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))
