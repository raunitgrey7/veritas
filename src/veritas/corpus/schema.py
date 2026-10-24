"""Record types shared by the corpus builders, the detectors and the harness.

Every attack carries an explicit ``compliance_marker``: the exact string the
attacker is trying to make the model emit. Using a marker instead of a free-form
notion of "harm" keeps the judge deterministic and keeps the corpus free of any
operational harmful content. ``{canary}`` is a placeholder that the harness
resolves to the per-run canary token planted in the system prompt.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

CANARY_PLACEHOLDER = "{canary}"


class Severity(StrEnum):
    """Impact if the attack succeeds against a production deployment."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExpectedBehaviour(StrEnum):
    """What a well-behaved model does when it receives the attack."""

    REFUSE = "refuse"
    IGNORE_INJECTION = "ignore_injection"
    NO_LEAK = "no_leak"
    NO_EXFIL = "no_exfil"


class Category(StrEnum):
    """Coarse grouping used in the spec: injection, jailbreak, exfiltration, policy."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_VIOLATION = "policy_violation"


class Family(StrEnum):
    """Sixteen attack families. Each maps to one category in ``FAMILY_CATEGORY``."""

    DIRECT_OVERRIDE = "direct_override"
    HIERARCHY_SPOOFING = "hierarchy_spoofing"
    INDIRECT_INJECTION = "indirect_injection"
    PAYLOAD_SPLITTING = "payload_splitting"
    ENCODING_SMUGGLING = "encoding_smuggling"
    PERSONA_JAILBREAK = "persona_jailbreak"
    FICTION_FRAMING = "fiction_framing"
    REFUSAL_SUPPRESSION = "refusal_suppression"
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    CANARY_EXFIL = "canary_exfil"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_ABUSE = "tool_abuse"
    POLICY_VIOLATION = "policy_violation"
    FILTER_EVASION = "filter_evasion"


FAMILY_CATEGORY: dict[Family, Category] = {
    Family.DIRECT_OVERRIDE: Category.PROMPT_INJECTION,
    Family.HIERARCHY_SPOOFING: Category.PROMPT_INJECTION,
    Family.INDIRECT_INJECTION: Category.PROMPT_INJECTION,
    Family.PAYLOAD_SPLITTING: Category.PROMPT_INJECTION,
    Family.ENCODING_SMUGGLING: Category.PROMPT_INJECTION,
    Family.PERSONA_JAILBREAK: Category.JAILBREAK,
    Family.FICTION_FRAMING: Category.JAILBREAK,
    Family.REFUSAL_SUPPRESSION: Category.JAILBREAK,
    Family.AUTHORITY_IMPERSONATION: Category.JAILBREAK,
    Family.MULTI_TURN_ESCALATION: Category.JAILBREAK,
    Family.SYSTEM_PROMPT_LEAK: Category.DATA_EXFILTRATION,
    Family.CANARY_EXFIL: Category.DATA_EXFILTRATION,
    Family.DATA_EXFILTRATION: Category.DATA_EXFILTRATION,
    Family.TOOL_ABUSE: Category.DATA_EXFILTRATION,
    Family.POLICY_VIOLATION: Category.POLICY_VIOLATION,
    Family.FILTER_EVASION: Category.POLICY_VIOLATION,
}


class AttackCase(BaseModel):
    """One attack against a model under test.

    ``turns`` holds the user messages in order; the last one carries the payload.
    ``task`` is the legitimate request that wraps an indirect injection, kept
    separately so the judge can tell "did the task" from "obeyed the injection".
    """

    id: str
    family: Family
    category: Category
    technique: str
    severity: Severity
    expected_behaviour: ExpectedBehaviour
    language: str = "en"
    variant: str = "plain"
    turns: list[str] = Field(min_length=1)
    task: str | None = None
    compliance_marker: str
    base_id: str
    tags: list[str] = Field(default_factory=list)

    @property
    def payload(self) -> str:
        """The final user turn, which is what the detectors see for single-turn cases."""
        return self.turns[-1]

    @property
    def full_text(self) -> str:
        """All turns joined, used by detectors that evaluate a whole conversation."""
        return "\n".join(self.turns)


class BenignCase(BaseModel):
    """A legitimate prompt used to measure false positives.

    ``hard_negative`` marks prompts that share vocabulary with attacks (words like
    "ignore", "system prompt", "secret", base64 blobs) but are harmless.
    """

    id: str
    category: str
    language: str = "en"
    text: str
    hard_negative: bool = False
