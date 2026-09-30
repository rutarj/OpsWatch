"""Policy engine: decides whether a proposed action is allowed, how risky it is, and who may approve it.

Rules live in config/policy.toml so a service desk manager can change them
without touching code. This is the core defense against OWASP LLM06 (excessive
agency): the model's power is limited by policy, not by trusting the model.
"""
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Decision:
    allowed: bool
    risk: str
    requires_approval: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class Policy:
    raw: dict

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with open(path, "rb") as fh:
            return cls(tomllib.load(fh))

    @property
    def approvers(self) -> set[str]:
        return set(self.raw["approval"]["approvers"])

    @property
    def high_risk_approvers(self) -> set[str]:
        return set(self.raw["approval"]["high_risk_approvers"])

    def evaluate(self, *, action: str, actor: str, ticket: dict, payload: dict, suspicious: bool,
                 recent_proposals: int, open_for_ticket: int, at: datetime | None = None) -> Decision:
        at = at or datetime.now(UTC)
        risk_table = self.raw["actions"]
        if action not in risk_table:
            return Decision(False, "high", True, [f"unknown action '{action}'"])

        risk = risk_table[action]
        reasons: list[str] = []
        blocked = False
        limits, rules = self.raw["limits"], self.raw["rules"]
        is_agent = actor.startswith("agent:")

        if recent_proposals >= limits["max_proposals_per_agent_per_hour"]:
            blocked = True
            reasons.append("rate limit: too many proposals from this agent in the last hour")
        if open_for_ticket >= limits["max_pending_per_ticket"]:
            blocked = True
            reasons.append("too many pending proposals already open on this ticket")

        if action == "resolve_ticket" and is_agent:
            if rules.get("block_agent_resolve_p1") and ticket.get("priority") == "P1":
                blocked = True
                reasons.append("agents may not resolve P1 incidents; escalate to a human")
            if ticket.get("category") in rules.get("block_agent_resolve_categories", []):
                blocked = True
                reasons.append(f"agents may not resolve '{ticket.get('category')}' incidents")

        if action == "create_change":
            window = self._active_freeze(at)
            if window:
                blocked = True
                reasons.append(f"change freeze '{window}' is active")

        if action == "update_ticket" and payload.get("fields", {}).get("state") in ("resolved", "closed"):
            risk = "high"
            reasons.append("state change to resolved/closed via update is treated as a resolution")

        if suspicious and rules.get("escalate_suspicious_tickets"):
            risk = "high"
            reasons.append("ticket text flagged as possible prompt injection; human review required")

        auto = self.raw["approval"].get("auto_approve_low_risk", False) and risk == "low" and not suspicious
        return Decision(allowed=not blocked, risk=risk, requires_approval=not auto, reasons=reasons)

    def can_approve(self, approver: str, risk: str) -> tuple[bool, str]:
        if approver.startswith("agent:"):
            return False, "agents cannot approve actions"
        if approver not in self.approvers:
            return False, f"'{approver}' is not an approver"
        if risk == "high" and approver not in self.high_risk_approvers:
            return False, f"'{approver}' cannot approve high-risk actions"
        return True, "ok"

    def _active_freeze(self, at: datetime) -> str | None:
        for window in self.raw.get("freeze_windows", []):
            if datetime.fromisoformat(window["start"]) <= at < datetime.fromisoformat(window["end"]):
                return window["name"]
        return None


def one_hour_ago() -> str:
    return (datetime.now(UTC) - timedelta(hours=1)).isoformat()
