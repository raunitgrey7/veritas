"""Attack and benign corpora.

``schema`` defines the case records, ``families`` holds the hand-written attack
templates grouped by family, ``variants`` applies seeded transformations
(encodings, obfuscation, languages, multi-turn splitting), ``generator`` composes
the two into a corpus, ``benign`` builds the matching negative set, and ``store``
reads and writes the JSONL files cached under ``data/``.
"""

from veritas.corpus.benign import build_benign_corpus
from veritas.corpus.generator import build_attack_corpus
from veritas.corpus.schema import AttackCase, BenignCase, ExpectedBehaviour, Family, Severity
from veritas.corpus.store import coverage, load_jsonl, save_jsonl

__all__ = [
    "AttackCase",
    "BenignCase",
    "ExpectedBehaviour",
    "Family",
    "Severity",
    "build_attack_corpus",
    "build_benign_corpus",
    "coverage",
    "load_jsonl",
    "save_jsonl",
]
