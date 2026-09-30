"""Append-only, tamper-evident audit log (a simple hash chain).

Every entry stores the hash of the previous entry. Changing or deleting any past
row breaks every hash after it, so `verify()` can prove the log wasn't edited.
This is the same idea used by certificate transparency logs and git history.
"""
import hashlib
import json
from datetime import UTC, datetime

GENESIS = "0" * 64


def _canonical(entry: dict) -> str:
    # Sorted keys + no whitespace = the same dict always produces the same string.
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, ts: str, actor: str, event: str, ticket_id: str | None, details: dict) -> str:
    payload = _canonical({"prev": prev_hash, "ts": ts, "actor": actor, "event": event,
                          "ticket_id": ticket_id, "details": details})
    return hashlib.sha256(payload.encode()).hexdigest()


def append(conn, actor: str, event: str, ticket_id: str | None = None, details: dict | None = None) -> str:
    details = details or {}
    row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    prev_hash = row[0] if row else GENESIS
    ts = datetime.now(UTC).isoformat()
    entry_hash = compute_hash(prev_hash, ts, actor, event, ticket_id, details)
    conn.execute(
        "INSERT INTO audit_log (ts, actor, event, ticket_id, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
        (ts, actor, event, ticket_id, _canonical(details), prev_hash, entry_hash),
    )
    return entry_hash


def verify(conn) -> dict:
    """Walk the chain from the start. Returns ok=False and the first bad seq if anything was altered."""
    prev_hash = GENESIS
    count = 0
    for seq, ts, actor, event, ticket_id, details, stored_prev, stored_hash in conn.execute(
        "SELECT seq, ts, actor, event, ticket_id, details, prev_hash, hash FROM audit_log ORDER BY seq"
    ):
        expected = compute_hash(prev_hash, ts, actor, event, ticket_id, json.loads(details))
        if stored_prev != prev_hash or stored_hash != expected:
            return {"ok": False, "entries_checked": count, "first_bad_seq": seq}
        prev_hash = stored_hash
        count += 1
    return {"ok": True, "entries_checked": count, "first_bad_seq": None}
