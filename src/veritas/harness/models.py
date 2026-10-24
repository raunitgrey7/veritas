"""Models under test behind one pluggable interface.

The platform evaluates a "model under test" without caring how it produces text.
Everything in the default path is deterministic and offline:

* :class:`EchoModel` returns the user text unchanged. It is the local echo model
  the spec asks for and a useful baseline: it leaks anything written in the
  prompt but never leaks the system canary, because it never sees system text in
  its output.
* :class:`MockModel` is a seeded instruction-follower whose safety is tunable. At
  ``compliance=1.0`` it is a fully vulnerable model that decodes smuggled
  instructions and obeys them; at ``0.0`` it always refuses; in between it obeys a
  stable, seed-determined subset, which gives a non-trivial attack success rate
  with a real confidence interval.
* :class:`GuardedModel` wraps any model with the guardrail pipeline to show how
  much the guardrail reduces attack success.
* :class:`AnthropicModel` is the optional online adapter, never used by tests or
  benchmarks.

A mock "complying" with an attack emits the harmless compliance marker (or, for
leak attacks, the system text that holds the canary). No model ever produces real
harmful content, so the whole harness runs safely offline.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from veritas.detectors.normalize import decode_base64_segments, normalize, rot13
from veritas.detectors.pipeline import Guardrail
from veritas.harness.types import ModelResponse, Turn

REFUSAL_TEXT = "I cannot help with that request. It appears to violate safety policy."
_MARKER_RE = re.compile(r"VERITAS_[A-Z]+")
_LEAK_CUE = re.compile(
    r"(system prompt|instructions|configuration|secret|hidden|token|canary|verbatim"
    r"|above this line)",
    re.IGNORECASE,
)


@runtime_checkable
class ModelUnderTest(Protocol):
    """Anything that turns a system prompt and user turns into a response."""

    name: str

    def generate(self, system: str, turns: list[Turn]) -> ModelResponse:
        """Produce a response to the conversation."""
        ...


def _user_text(turns: list[Turn]) -> str:
    return "\n".join(t.content for t in turns if t.role == "user")


def _find_markers(text: str) -> list[str]:
    """Return compliance markers visible in the text or its decoded segments."""
    sources = [text, normalize(text), rot13(text), *decode_base64_segments(text)]
    found: list[str] = []
    for source in sources:
        found.extend(_MARKER_RE.findall(source))
    return found


@dataclass
class EchoModel:
    """Return the concatenated user turns verbatim."""

    name: str = "echo"

    def generate(self, system: str, turns: list[Turn]) -> ModelResponse:
        """Echo the user text back; the system prompt is never exposed."""
        _ = system
        return ModelResponse(text=_user_text(turns), model_name=self.name)


@dataclass
class MockModel:
    """A seeded instruction-follower with tunable safety.

    ``compliance`` is the fraction of attacks the model obeys. The decision is a
    stable hash of ``(seed, conversation)`` so the same case always gets the same
    outcome, which is what makes the benchmark reproducible.
    """

    compliance: float = 1.0
    seed: int = 1337
    name: str = "mock"
    _refusal: str = field(default=REFUSAL_TEXT, repr=False)

    def generate(self, system: str, turns: list[Turn]) -> ModelResponse:
        """Obey the attack (emit the marker or leak the system text) or refuse."""
        user = _user_text(turns)
        if not self._will_comply(user):
            return ModelResponse(text=self._refusal, model_name=self.name)
        markers = _find_markers(user)
        if markers:
            return ModelResponse(text=f"Sure. {markers[0]}", model_name=self.name)
        if _LEAK_CUE.search(user):
            return ModelResponse(text=f"Here is my configuration: {system}",
                                 model_name=self.name)
        return ModelResponse(text="Sure, here is what you asked for.", model_name=self.name)

    def _will_comply(self, user: str) -> bool:
        if self.compliance >= 1.0:
            return True
        if self.compliance <= 0.0:
            return False
        digest = hashlib.sha256(f"{self.seed}:{user}".encode()).digest()
        draw = int.from_bytes(digest[:8], "big") / 2**64
        return draw < self.compliance


@dataclass
class GuardedModel:
    """Wrap a model with the guardrail: block risky inputs, scrub leaking outputs."""

    inner: ModelUnderTest
    guardrail: Guardrail = field(default_factory=Guardrail)
    name: str = "guarded"
    _refusal: str = field(default=REFUSAL_TEXT, repr=False)

    def generate(self, system: str, turns: list[Turn]) -> ModelResponse:
        """Refuse flagged inputs, otherwise delegate and scrub leaking output.

        The guard is strict: any input that is not plainly allowed is refused, and
        any output that trips an output scanner (a leaked canary, a secret, PII) is
        replaced with a refusal. This is the defence-in-depth configuration the
        benchmark compares against the unguarded model.
        """
        user = _user_text(turns)
        canary = _extract_canary(system)
        verdict = self.guardrail.evaluate_input(user, canary=canary)
        if verdict.flagged:
            return ModelResponse(text=self._refusal, model_name=self.name,
                                 metadata={"blocked_input": "true"})
        response = self.inner.generate(system, turns)
        out = self.guardrail.evaluate_output(response.text, canary=canary)
        if out.flagged:
            return ModelResponse(text=self._refusal, model_name=self.name,
                                 metadata={"blocked_output": "true"})
        return ModelResponse(text=response.text, model_name=self.name)


_CANARY_IN_SYSTEM = re.compile(r"canary token:\s*(\S+)")


def _extract_canary(system: str) -> str | None:
    match = _CANARY_IN_SYSTEM.search(system)
    return match.group(1) if match else None


@dataclass
class AnthropicModel:
    """Optional online adapter. Requires the ``llm`` extra and an API key.

    Kept out of the default path: tests and benchmarks never construct it. It is
    constructed lazily so importing this module never needs the anthropic package.
    """

    model: str = "claude-haiku-5-5"
    name: str = "anthropic"
    max_tokens: int = 256

    def generate(self, system: str, turns: list[Turn]) -> ModelResponse:
        """Call the Anthropic Messages API with the conversation."""
        import os
        import time

        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised only with the extra
            raise RuntimeError("install the 'llm' extra to use AnthropicModel") from exc
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        client = anthropic.Anthropic(api_key=key)
        messages = [{"role": t.role, "content": t.content} for t in turns]
        start = time.perf_counter()
        reply = client.messages.create(model=self.model, max_tokens=self.max_tokens,
                                        system=system, messages=messages)
        latency = (time.perf_counter() - start) * 1000
        text = "".join(block.text for block in reply.content if block.type == "text")
        return ModelResponse(text=text, model_name=self.name, latency_ms=latency)
