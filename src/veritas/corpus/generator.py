"""Compose base templates and seeded variants into the attack corpus.

The corpus is a deterministic function of the templates and the variant set, so
it carries no explicit seed argument: the same code always yields the same cases
with the same ids. A ``seed`` is accepted and recorded for forward compatibility
with future stochastic generators and to document provenance in the JSONL store.
"""

from __future__ import annotations

from veritas import DEFAULT_SEED
from veritas.corpus.families import BaseTemplate, all_templates
from veritas.corpus.schema import FAMILY_CATEGORY, AttackCase
from veritas.corpus.variants import expand_payload


def _base_id(index: int, template: BaseTemplate) -> str:
    return f"{template.family.value}.{template.technique}.{index:02d}"


def _case_from(index: int, template: BaseTemplate, variant: str, language: str,
               turns: tuple[str, ...]) -> AttackCase:
    base_id = _base_id(index, template)
    return AttackCase(
        id=f"{base_id}:{variant}",
        family=template.family,
        category=FAMILY_CATEGORY[template.family],
        technique=template.technique,
        severity=template.severity,
        expected_behaviour=template.expected_behaviour,
        language=language,
        variant=variant,
        turns=list(turns),
        task=template.task,
        compliance_marker=template.compliance_marker,
        base_id=base_id,
        tags=list(template.tags),
    )


def build_attack_corpus(seed: int = DEFAULT_SEED) -> list[AttackCase]:
    """Return the full attack corpus, sorted by id for stable ordering.

    ``seed`` is accepted for API symmetry with :func:`build_benign_corpus` and is
    not otherwise used: expansion is deterministic by construction.
    """
    _ = seed
    cases: list[AttackCase] = []
    for index, template in enumerate(all_templates()):
        for variant, language, turns in expand_payload(template):
            cases.append(_case_from(index, template, variant, language, turns))
    cases.sort(key=lambda c: c.id)
    _check_invariants(cases)
    return cases


def _check_invariants(cases: list[AttackCase]) -> None:
    """Fail loudly if the corpus violates a property the rest of the code relies on."""
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate attack ids in corpus")
    families = {c.family for c in cases}
    if len(families) < 12:
        raise ValueError(f"corpus covers only {len(families)} families, need at least 12")
