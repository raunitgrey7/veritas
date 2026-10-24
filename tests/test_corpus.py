"""Tests for the attack and benign corpora and their invariants."""

from __future__ import annotations

import pytest

from veritas.corpus import build_attack_corpus, coverage
from veritas.corpus.families import all_templates
from veritas.corpus.schema import CANARY_PLACEHOLDER, FAMILY_CATEGORY, Family


def test_corpus_meets_minimum_size(attacks):
    assert len(attacks) >= 400


def test_corpus_covers_at_least_twelve_families(attacks):
    assert len({a.family for a in attacks}) >= 12


def test_corpus_covers_all_sixteen_families(attacks):
    assert {a.family for a in attacks} == set(Family)


def test_benign_meets_minimum_size(benign):
    assert len(benign) >= 400


def test_benign_has_hard_negatives(benign):
    assert sum(1 for b in benign if b.hard_negative) >= 20


def test_attack_ids_are_unique(attacks):
    ids = [a.id for a in attacks]
    assert len(ids) == len(set(ids))


def test_benign_ids_are_unique(benign):
    ids = [b.id for b in benign]
    assert len(ids) == len(set(ids))


def test_every_attack_has_at_least_one_turn(attacks):
    assert all(len(a.turns) >= 1 for a in attacks)


def test_every_attack_has_a_compliance_marker(attacks):
    assert all(a.compliance_marker for a in attacks)


def test_category_matches_family_mapping(attacks):
    assert all(a.category == FAMILY_CATEGORY[a.family] for a in attacks)


def test_multiple_languages_present(attacks):
    assert {a.language for a in attacks} >= {"en", "hi", "es", "fr"}


def test_multi_turn_family_has_multi_turn_cases(attacks):
    multi = [a for a in attacks if a.family is Family.MULTI_TURN_ESCALATION]
    assert any(len(a.turns) >= 2 for a in multi)


def test_leak_families_use_canary_placeholder():
    templates = all_templates()
    leak = [t for t in templates if t.family in
            {Family.SYSTEM_PROMPT_LEAK, Family.CANARY_EXFIL, Family.DATA_EXFILTRATION}]
    assert leak and all(t.compliance_marker == CANARY_PLACEHOLDER for t in leak)


def test_payload_property_returns_last_turn(attacks):
    case = attacks[0]
    assert case.payload == case.turns[-1]


def test_full_text_joins_all_turns():
    case = next(a for a in build_attack_corpus() if len(a.turns) >= 2)
    assert case.full_text == "\n".join(case.turns)


def test_coverage_counts_are_consistent(attacks, benign):
    cov = coverage(attacks, benign)
    assert cov["attack_total"] == len(attacks)
    assert cov["benign_total"] == len(benign)
    assert sum(cov["by_family"].values()) == len(attacks)


def test_coverage_by_variant_sums_to_total(attacks, benign):
    cov = coverage(attacks, benign)
    assert sum(cov["by_variant"].values()) == len(attacks)


@pytest.mark.parametrize("family", list(Family))
def test_each_family_has_cases(attacks, family):
    assert any(a.family is family for a in attacks)
