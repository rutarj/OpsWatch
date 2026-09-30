"""Redact personal data before ticket text is sent to an external LLM (OWASP LLM02).

Ops-relevant details like hostnames and IP addresses are deliberately kept:
engineers need them, and they aren't personal data about the caller.
"""
import re

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
SIN = re.compile(r"(?<!\d)\d{3}[\s-]\d{3}[\s-]\d{3}(?!\d)")  # Canadian Social Insurance Number format
CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum: real card numbers pass it, most random digit strings don't (fewer false positives)."""
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Return redacted text and a count of what was removed (counts go in the audit log, values never do)."""
    counts = {"email": 0, "phone": 0, "sin": 0, "card": 0}

    def card_sub(match):
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            counts["card"] += 1
            return "[CARD]"
        return match.group()

    text = CARD_CANDIDATE.sub(card_sub, text)
    text, counts["email"] = EMAIL.subn("[EMAIL]", text)
    text, counts["sin"] = SIN.subn("[SIN]", text)
    text, counts["phone"] = PHONE.subn("[PHONE]", text)
    return text, {k: v for k, v in counts.items() if v}
