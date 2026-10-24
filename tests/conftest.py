"""Shared fixtures. The corpora are built once per session for speed."""

from __future__ import annotations

import pytest

from veritas.corpus import build_attack_corpus, build_benign_corpus
from veritas.detectors import Guardrail


@pytest.fixture(scope="session")
def attacks():
    return build_attack_corpus()


@pytest.fixture(scope="session")
def benign():
    return build_benign_corpus()


@pytest.fixture(scope="session")
def guardrail():
    return Guardrail()
