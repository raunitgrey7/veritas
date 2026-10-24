"""veritas: deterministic LLM evaluation, red-teaming and guardrail platform.

The package is organised around four questions a safety team asks of a model
deployment: what attacks exist (``veritas.corpus``), which of them a guardrail
catches (``veritas.detectors``), how often a model under test actually complies
(``veritas.harness``), and whether a new release got worse (``veritas.gate``).
Everything in the default path is deterministic and runs without network access
or API keys so that benchmarks are reproducible from a single seed.
"""

__version__ = "0.1.0"

DEFAULT_SEED = 1337
"""Seed used by the benchmark, the corpus builder and every test fixture."""
