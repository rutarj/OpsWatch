"""Heuristic prompt-injection detector for ticket text (OWASP LLM01).

Tickets are written by anyone who can email the service desk, so their text is
untrusted input. This detector is the FIRST layer only. The real protection is
structural: the agent cannot approve its own actions, so even a successful
injection can at most create a proposal that a human then rejects.
"""
import re
from dataclasses import dataclass, field

PATTERNS: list[tuple[str, str]] = [
    ("override_instructions", r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instruction|prompt|rule|polic|guideline)"),
    ("role_hijack", r"\byou are (now|no longer)\b|\bact as\b.{0,30}\b(admin|administrator|root|system)|\bnew (role|persona)\b"),
    ("system_prompt_probe", r"\b(system prompt|hidden instructions|your instructions|developer message)\b"),
    ("tool_manipulation", r"\b(call|use|invoke|run)\b.{0,20}\b(tool|function|propose_\w+|approve)\b"),
    ("bulk_destructive", r"\b(close|resolve|delete|approve|reset)\b.{0,15}\b(all|every|each)\b.{0,15}\b(ticket|incident|account|password|request)s?\b"),
    ("self_approval", r"\b(auto[- ]?approve|approve (this|it|yourself)|mark (it|this) (as )?approved|skip (the )?approval)\b"),
    ("exfiltration", r"\b(send|email|post|upload|forward)\b.{0,40}\b(password|credential|token|api key|secret)s?\b"),
    ("fake_markup", r"</?(system|assistant|tool|instructions?)>|\[\[?(system|admin)\]?\]"),
]
COMPILED = [(name, re.compile(rx, re.IGNORECASE | re.DOTALL)) for name, rx in PATTERNS]


@dataclass
class InjectionScan:
    suspicious: bool
    score: float
    matches: list[str] = field(default_factory=list)


def scan(text: str) -> InjectionScan:
    matches = [name for name, rx in COMPILED if rx.search(text)]
    score = min(1.0, 0.5 * len(matches))
    return InjectionScan(suspicious=bool(matches), score=score, matches=matches)
