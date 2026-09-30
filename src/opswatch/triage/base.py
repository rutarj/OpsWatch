"""Shared triage output shape. Every triager (rules, ML, LLM, hybrid) returns exactly this."""
from dataclasses import asdict, dataclass, field


@dataclass
class TriageResult:
    category: str
    priority: str
    assignment_group: str
    confidence: float
    method: str
    rationale: str = ""
    impact: int | None = None
    urgency: int | None = None
    suggested_kb: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    needs_human_review: bool = False
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def ticket_text(ticket: dict) -> str:
    return f"{ticket.get('short_description', '')}\n{ticket.get('description', '')}".strip()
