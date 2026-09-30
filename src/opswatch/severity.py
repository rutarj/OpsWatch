"""Severity policy for machine-generated monitoring alerts.

Alarms don't say "I can't work" like a person does, so priority can't come from
phrasing. It comes from what the alarm means for customers. One shared table is
used by the dataset generator, the rules triager and the SNS alarm handler, so
they can never disagree. Order matters: the first matching key wins.
"""
ALARM_SEVERITY: list[tuple[str, tuple[int, int]]] = [
    # (keyword, (impact, urgency))
    ("5xx", (1, 1)),               # customers get errors: P1
    ("502", (1, 1)),
    ("503", (1, 1)),
    ("server errors", (1, 1)),
    ("dlq", (2, 1)),               # data failing to process: P2
    ("dead-letter", (2, 1)),
    ("errors", (2, 1)),
    ("timing out", (2, 1)),
    ("failing with errors", (2, 1)),
    ("backlog", (2, 2)),           # slower, not failing: P3
    ("falling behind", (2, 2)),
    ("throttl", (2, 2)),
    ("did not run", (3, 2)),       # internal job: P4
    ("didn't trigger", (3, 2)),
    ("report", (3, 2)),
    ("budget", (3, 3)),
]
DEFAULT = (2, 2)


def alarm_severity(text: str) -> tuple[int, int]:
    lowered = text.lower()
    for key, severity in ALARM_SEVERITY:
        if key in lowered:
            return severity
    return DEFAULT
