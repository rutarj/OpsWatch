"""Baseline 1: hand-written keyword rules. No ML, no API, fully explainable.

Anti-leakage rule: every keyword must appear in the TRAINING tickets (enforced by
tests/test_triage.py::test_rules_lexicon_is_derived_from_training_data). An earlier
version included phrases that only existed in the held-out test set, which inflated
the scores. They were removed; see NOTES.md, "Decisions".

Every AI system should be compared against a dumb baseline. If the LLM can't
beat 60 lines of keywords, it isn't worth its cost.
"""
import re
import time

from opswatch.severity import alarm_severity
from opswatch.taxonomy import Category, group_for, priority_for
from opswatch.triage.base import TriageResult, ticket_text

KEYWORDS: dict[Category, list[str]] = {
    Category.ACCESS_IDENTITY: [
        "password", "locked", "mfa", "authenticator", "sign in", "sign-in", "login", "sso", "access",
        "permission", "credentials", "account",
    ],
    Category.HARDWARE: [
        "laptop", "monitor", "dock", "keyboard", "mouse", "printer", "battery", "screen", "desktop",
        "headset", "display", "blue screen", "power on",
    ],
    Category.NETWORK: [
        "wi-fi", "wireless", "vpn", "ethernet", "network", "dns", "internet", "latency", "switch", "resolve",
        "jack",
    ],
    Category.SOFTWARE: [
        "install", "license", "crash", "update", "error", "application", "app", "excel", "macro", "plugin",
        "freezes",
    ],
    Category.AV_CLASSROOM: [
        "projector", "hyflex", "classroom", "lecture", "room", "ceiling mic", "microphone", "touch panel",
        "hdmi", "lectern", "document camera", "speakers", "zoom room",
    ],
    Category.EMAIL_COLLAB: [
        "outlook", "email", "mailbox", "teams", "calendar", "invite", "distribution list", "outbox",
        "attachment", "out of office",
    ],
    Category.SECURITY: [
        "phishing", "suspicious", "malware", "ransomware", "antivirus", "stolen", "clicked a link",
        "lookalike", "sign-in from", "public link", "usb", "threat",
    ],
    Category.CLOUD_OPS: [
        "[alarm]", "cloudwatch", "lambda", "dead-letter", "dlq", "queue", "dynamodb", "throttl", "s3",
        "eventbridge", "aws", "5xx", "budget",
    ],
}
# Phrases that say how many people are affected / how blocked they are.
IMPACT_HINTS = {
    1: ["whole campus", "everyone in the organization", "all users"],
    2: ["team", "department", "floor", "finance"],
}
URGENCY_HINTS = {
    1: ["can't work", "blocking", "urgent", "stopped", "stuck", "deadline"],
    3: ["no rush", "not urgent", "next week", "whenever", "can wait"],
}
WORD = re.compile(r"[a-z0-9\-\[\]']+")


def _score(text: str) -> dict[Category, float]:
    lowered = text.lower()
    scores = {}
    for cat, words in KEYWORDS.items():
        # multi-word phrases count double: they're more specific than single words
        scores[cat] = sum((2.0 if " " in w else 1.0) for w in words if w in lowered)
    return scores


def estimate_impact_urgency(text: str) -> tuple[int, int]:
    lowered = text.lower()

    def hit(hints):
        return any(h in lowered for h in hints)

    impact = 1 if hit(IMPACT_HINTS[1]) else 2 if hit(IMPACT_HINTS[2]) else 3
    urgency = 1 if hit(URGENCY_HINTS[1]) else 3 if hit(URGENCY_HINTS[3]) else 2
    return impact, urgency


class RulesTriager:
    name = "rules"

    def triage(self, ticket: dict) -> TriageResult:
        start = time.perf_counter()
        text = ticket_text(ticket)
        scores = _score(text)
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        (best, top), (_, second) = ranked[0], ranked[1]
        if top == 0:
            best = Category.SOFTWARE  # catch-all when nothing matches
        confidence = 0.0 if top == 0 else round(top / (top + second), 3)
        if ticket.get("source") == "monitoring":
            best = Category.CLOUD_OPS
            confidence = max(confidence, 0.9)
            impact, urgency = alarm_severity(text)  # alarms: severity policy, not phrasing
        else:
            impact, urgency = estimate_impact_urgency(text)
        return TriageResult(
            category=best.value, priority=priority_for(impact, urgency).value, assignment_group=group_for(best),
            confidence=confidence, method=self.name, impact=impact, urgency=urgency,
            rationale=f"keyword score {top:g} vs runner-up {second:g}",
            latency_ms=round((time.perf_counter() - start) * 1000, 3),
        )
