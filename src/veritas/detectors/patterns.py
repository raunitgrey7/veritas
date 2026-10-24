"""Keyword and phrase detector for injection, jailbreak, leak and policy cues.

Patterns run against :func:`veritas.detectors.normalize.normalize` output, so one
rule catches a phrase and its leetspeak, homoglyph and zero-width variants. A
handful of Hinglish, Spanish and French trigger words extend coverage to the
translated variants without a full multilingual model.

Each rule carries a category and a score. Scores are deliberately below 1.0 for
single weak cues so the pipeline can combine signals rather than block on one
ambiguous word; the strongest, least ambiguous phrases score highest.
"""

from __future__ import annotations

import re

from veritas.detectors.base import DetectionResult, Signal, result
from veritas.detectors.normalize import normalize

# (compiled pattern, category, score, explanation). Patterns match normalised text.
_RULES: list[tuple[re.Pattern[str], str, float, str]] = [
    # Direct instruction override.
    (re.compile(r"ignore (all |the |your )?(previous|prior|above|earlier) (instructions|rules|messages|prompts)"),
     "prompt_injection", 0.9, "asks the model to ignore prior instructions"),
    (re.compile(r"disregard (all |the |your |every )?(previous |prior )?(instructions?|rules?|guidelines?)"),
     "prompt_injection", 0.9, "asks the model to disregard its rules"),
    (re.compile(r"ignore (the user|the task|what the user|my earlier|everything (above|before))"),
     "prompt_injection", 0.85, "tells the model to ignore the user or context"),
    (re.compile(r"your only task( now)? is to (print|output|say|reply|write)"),
     "prompt_injection", 0.75, "redefines the model's only task"),
    (re.compile(r"the (literal|exact) string"), "prompt_injection", 0.6,
     "demands a specific literal string as output"),
    (re.compile(r"forget (the above|everything|your (rules|instructions))"),
     "prompt_injection", 0.85, "asks the model to forget its instructions"),
    (re.compile(r"new instructions?\s*:"), "prompt_injection", 0.7,
     "introduces replacement instructions"),
    (re.compile(r"(output|respond|reply|answer|print|say) (with )?exactly"),
     "prompt_injection", 0.7, "demands an exact scripted output"),
    (re.compile(r"(respond|reply|answer) with (the )?(single |one |only )?(word|string|phrase|token|value|line)"),
     "prompt_injection", 0.7, "scripts the exact response the attacker wants"),
    (re.compile(r"your (reply|answer|response|output) must (equal|be|only be)"),
     "prompt_injection", 0.7, "forces the response to a fixed value"),
    (re.compile(r"whatever (your |the )?rules (say|are)"), "prompt_injection", 0.7,
     "explicitly tries to beat the rules"),
    (re.compile(r"follow\s+\w(\s*\+\s*\w)+"), "prompt_injection", 0.75,
     "assembles an instruction from concatenated parts"),
    # Jailbreak personas and refusal suppression.
    (re.compile(r"you are now (dan|an? (unrestricted|unfiltered|jailbroken))"),
     "jailbreak", 0.9, "invokes a jailbreak persona"),
    (re.compile(r"\bdan\b.*(no restrictions|never refuses)"), "jailbreak", 0.8,
     "DAN-style unrestricted persona"),
    (re.compile(r"(developer|opposite|god) mode"), "jailbreak", 0.75,
     "requests a special unrestricted mode"),
    (re.compile(r"(unfiltered|unrestricted|no restrictions|policy disabled|without restrictions|rules are reversed|rules reversed|no prior rules)"),
     "jailbreak", 0.7, "claims the model has no restrictions"),
    (re.compile(r"skip (your |the )?(usual )?(checks|safety|review|guardrails)"),
     "jailbreak", 0.7, "asks the model to skip its safety checks"),
    (re.compile(r"(pretend|act as|imagine) (you are|to be) (an? )?(unfiltered|unrestricted|model with|ai with)"),
     "jailbreak", 0.7, "role-play into an unrestricted model"),
    (re.compile(r"do not (refuse|apologi[sz]e|warn|add warnings)"), "jailbreak", 0.75,
     "forbids the model from refusing"),
    (re.compile(r"forbidden from using the words"), "jailbreak", 0.75,
     "bans refusal vocabulary"),
    (re.compile(r"(begin|start) your (answer|reply|response) with"), "jailbreak", 0.6,
     "prefix injection to pre-empt a refusal"),
    (re.compile(r"as (dan|the villain|my (grandmother|grandma|late grandmother))"), "jailbreak", 0.6,
     "role-play framing to bypass policy"),
    (re.compile(r"(authori[sz]ation granted|i am the (lead )?(developer|admin)|sanctioned test|safety team|law enforcement|legal authority|official request)"),
     "jailbreak", 0.7, "claims privileged authority"),
    # Fiction / hypothetical framing.
    (re.compile(r"(include|say|speak|write|output|print) (the |it |them )?(exact|literal|magic) (word|words|phrase|string|line)"),
     "jailbreak", 0.65, "asks for the exact forbidden string under a fiction frame"),
    (re.compile(r"if you had no (rules|restrictions)"), "jailbreak", 0.65,
     "hypothetical with no rules"),
    (re.compile(r"(villain'?s|character'?s) line (is|which)"), "jailbreak", 0.55,
     "wraps the payload as a script line"),
    # Data exfiltration and system-prompt leak.
    (re.compile(r"(repeat|print|reveal|show|dump|quote|send|spell)(\s+\w+){0,4}?\s+(system prompt|instructions|configuration|hidden token|secret|token)"),
     "data_exfiltration", 0.9, "asks the model to reveal its prompt, config or secrets"),
    (re.compile(r"(repeat|print|output) (everything|all)( above| of the above)? (this line )?verbatim"),
     "data_exfiltration", 0.85, "asks the model to echo the context verbatim"),
    (re.compile(r"(what were|tell me) (the |your )?(exact )?(initial |original )?instructions"),
     "data_exfiltration", 0.8, "asks for the original instructions"),
    (re.compile(r"(secret|hidden) (token|key|canary)"), "data_exfiltration", 0.8,
     "targets a secret token"),
    (re.compile(r"(letter by letter|spell (it |out )?letter)"), "data_exfiltration", 0.6,
     "asks the model to spell a value out to dodge filters"),
    (re.compile(r"(debug mode|verbose mode).{0,20}(dump|reveal|print|configuration)"),
     "data_exfiltration", 0.7, "fake debug mode to extract configuration"),
    # Policy-violating requests, guarded by a request verb to avoid benign mentions.
    (re.compile(r"(need|want|provide|give me|write|create|build|make|generate|produce|fulfil|fulfill|answer).{0,45}(malware|ransomware|spyware|phishing kit|exploit kit|self[- ]harm|dangerous device|bioweapon|explosive)"),
     "policy_violation", 0.85, "requests disallowed harmful content"),
    (re.compile(r"(restricted|disallowed|banned|prohibited|forbidden|b.nned) (content|request|material|information)"),
     "policy_violation", 0.8, "explicitly requests restricted content"),
    (re.compile(r"(credentials?|banking|password).{0,15}(harvest|theft|steal|phish)"),
     "policy_violation", 0.8, "requests credential theft tooling"),
    (re.compile(r"(home address|real name and address|whereabouts).{0,20}(of|and)"),
     "policy_violation", 0.7, "requests private personal information"),
    (re.compile(r"(provide|give|write|produce|generate|answer) (it |them |this )?(in full|step[- ]by[- ]step|full instructions)"),
     "policy_violation", 0.6, "asks for a full harmful walkthrough"),
    # Indirect injection cues inside embedded content.
    (re.compile(r"(note to ai|ai[,:]\s*(ignore|disregard|the)|\[\[assistant|assistant:\s*(disregard|ignore)|to the assistant:)"),
     "prompt_injection", 0.8, "instruction embedded for the assistant inside content"),
    (re.compile(r"(^|[^a-z])system\s*:\s*(the|you|ignore|disregard|new)"),
     "prompt_injection", 0.6, "inline fake system directive inside content"),
    # Encoding smuggling phrasing (the blob is handled by the encoding detector).
    (re.compile(r"(do what it says|then (also )?(obey|comply|follow)|reveal and comply|and obey|decode .{0,15}(obey|follow|comply)|(interpret|reveal) (the |this )?(escape|cipher|ciphered)|and echo it)"),
     "prompt_injection", 0.6, "instructs the model to decode and obey hidden text"),
    # Multilingual trigger words (Hinglish, Spanish, French).
    (re.compile(r"(ignora|ignore karo|olvida|oublie|bhool jao)"), "prompt_injection", 0.6,
     "non-English instruction-override cue"),
    (re.compile(r"(instrucciones|niyam|reglas|regles|gupt|jeton|secreto|secret)"),
     "prompt_injection", 0.45, "non-English reference to rules, secrets or tokens"),
    (re.compile(r"(di|bolo|chaapo|escribe|imprime|likho|responde|reponds) (el |la |the )?(secreto|token|gupt|jeton)"),
     "data_exfiltration", 0.6, "non-English request to output a secret or token"),
]


class PatternDetector:
    """Regex detector over normalised text."""

    name = "pattern"

    def scan(self, text: str, *, canary: str | None = None) -> DetectionResult:
        """Return a signal for every rule that matches the normalised text."""
        _ = canary
        normalised = normalize(text)
        signals: list[Signal] = []
        for pattern, category, score, explanation in _RULES:
            match = pattern.search(normalised)
            if match:
                signals.append(Signal(
                    detector=self.name, category=category, score=score,
                    explanation=explanation, evidence=_excerpt(match.group(0))))
        return result(self.name, signals)


def _excerpt(matched: str, limit: int = 60) -> str:
    return matched if len(matched) <= limit else matched[:limit] + "..."
