"""Tests for the seeded variant generator and its transforms."""

from __future__ import annotations

from veritas.corpus.families import INJECT_MARKER, all_templates
from veritas.corpus.variants import _split_turns, expand_payload, variant_names


def _single_turn_template():
    return next(t for t in all_templates() if len(t.turns) == 1)


def test_plain_variant_is_first_and_identity():
    template = _single_turn_template()
    variants = expand_payload(template)
    assert variants[0][0] == "plain"
    assert variants[0][2] == template.turns


def test_expansion_produces_multiple_variants():
    template = _single_turn_template()
    assert len(expand_payload(template)) >= 5


def test_variants_are_deduplicated():
    template = _single_turn_template()
    turn_sets = [turns for _, _, turns in expand_payload(template)]
    assert len(turn_sets) == len(set(turn_sets))


def test_marker_preserved_by_character_transforms():
    template = next(t for t in all_templates()
                    if t.compliance_marker == INJECT_MARKER and len(t.turns) == 1)
    for name, _lang, turns in expand_payload(template):
        if name in {"leetspeak", "homoglyph", "zero_width", "lang_hi", "lang_es", "lang_fr"}:
            assert INJECT_MARKER in "".join(turns)


def test_base64_variant_hides_plain_marker():
    template = next(t for t in all_templates()
                    if t.compliance_marker == INJECT_MARKER and len(t.turns) == 1)
    b64 = next(turns for name, _l, turns in expand_payload(template) if name == "base64")
    assert INJECT_MARKER not in "".join(b64)


def test_language_variants_tagged_with_language():
    template = _single_turn_template()
    langs = {lang for name, lang, _t in expand_payload(template) if name.startswith("lang_")}
    assert langs <= {"hi", "es", "fr"} and langs


def test_multiturn_only_for_single_turn_templates():
    single = _single_turn_template()
    names = {name for name, _l, _t in expand_payload(single)}
    assert "multiturn" in names
    multi = next(t for t in all_templates() if len(t.turns) > 1)
    multi_names = {name for name, _l, _t in expand_payload(multi)}
    assert "multiturn" not in multi_names


def test_split_turns_produces_two_parts():
    result = _split_turns("one two three four five six")
    assert len(result) == 2


def test_split_turns_keeps_short_payload_single():
    assert _split_turns("tiny") == ("tiny",)


def test_variant_names_includes_plain_and_multiturn():
    names = variant_names()
    assert "plain" in names and "multiturn" in names and "base64" in names


def test_generation_is_deterministic():
    template = _single_turn_template()
    assert expand_payload(template) == expand_payload(template)
