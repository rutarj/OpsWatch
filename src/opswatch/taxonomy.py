"""The service desk's vocabulary: categories, assignment groups and the ITIL priority matrix.

Kept in one module so the rules triager, the ML model, the LLM prompt, the MCP
server and the eval all agree on exactly the same labels.
"""
from enum import StrEnum


class Category(StrEnum):
    ACCESS_IDENTITY = "access_identity"
    HARDWARE = "hardware"
    NETWORK = "network"
    SOFTWARE = "software"
    AV_CLASSROOM = "av_classroom"
    EMAIL_COLLAB = "email_collab"
    SECURITY = "security"
    CLOUD_OPS = "cloud_ops"


class Priority(StrEnum):
    P1 = "P1"  # critical
    P2 = "P2"  # high
    P3 = "P3"  # moderate
    P4 = "P4"  # low


ASSIGNMENT_GROUPS: dict[Category, str] = {
    Category.ACCESS_IDENTITY: "Identity & Access",
    Category.HARDWARE: "Desktop Support",
    Category.NETWORK: "Network Operations",
    Category.SOFTWARE: "Application Support",
    Category.AV_CLASSROOM: "AV & Classroom Technology",
    Category.EMAIL_COLLAB: "Messaging & Collaboration",
    Category.SECURITY: "Security Operations",
    Category.CLOUD_OPS: "Cloud Operations",
}

CATEGORY_DESCRIPTIONS: dict[Category, str] = {
    Category.ACCESS_IDENTITY: "Passwords, account lockouts, MFA, permissions and access requests",
    Category.HARDWARE: "Laptops, desktops, monitors, docks, printers, peripherals",
    Category.NETWORK: "Wi-Fi, VPN, wired connectivity, DNS, slow network",
    Category.SOFTWARE: "Business applications, installs, licenses, crashes, errors",
    Category.AV_CLASSROOM: "Projectors, room displays, classroom and hybrid (HyFlex) room audio/video",
    Category.EMAIL_COLLAB: "Outlook, shared mailboxes, calendars, Teams",
    Category.SECURITY: "Phishing, suspicious logins, malware, data exposure",
    Category.CLOUD_OPS: "Cloud monitoring alerts: queues, dead-letter queues, function errors, API errors",
}

# ITIL priority matrix: impact (1 = widespread, 3 = one person) x urgency (1 = blocked now, 3 = can wait).
PRIORITY_MATRIX: dict[tuple[int, int], Priority] = {
    (1, 1): Priority.P1, (1, 2): Priority.P2, (1, 3): Priority.P3,
    (2, 1): Priority.P2, (2, 2): Priority.P3, (2, 3): Priority.P4,
    (3, 1): Priority.P3, (3, 2): Priority.P4, (3, 3): Priority.P4,
}

TICKET_STATES = ("new", "in_progress", "on_hold", "resolved", "closed")


def priority_for(impact: int, urgency: int) -> Priority:
    """Derive priority the ITIL way instead of letting anyone pick it freely."""
    return PRIORITY_MATRIX[(impact, urgency)]


def group_for(category: str) -> str:
    return ASSIGNMENT_GROUPS[Category(category)]
