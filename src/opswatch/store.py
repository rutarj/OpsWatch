"""SQLite-backed mock ITSM (a stand-in for ServiceNow's incident, change and KB tables).

SQLite keeps the project runnable anywhere with zero setup. The Store class is the
only place that touches SQL, so swapping in Postgres or a real ServiceNow API
later means changing this file, not the rest of the app.
"""
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from opswatch import audit

SCHEMA = """
CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL DEFAULT 'incident',
    short_description TEXT NOT NULL,
    description TEXT NOT NULL,
    caller TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'portal',
    category TEXT,
    priority TEXT,
    impact INTEGER,
    urgency INTEGER,
    assignment_group TEXT,
    state TEXT NOT NULL DEFAULT 'new',
    resolution_notes TEXT,
    parent_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS work_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL REFERENCES tickets(id),
    author TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kb_articles (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL,
    action TEXT NOT NULL,
    payload TEXT NOT NULL,
    rationale TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    risk TEXT NOT NULL,
    status TEXT NOT NULL,
    policy_notes TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    result TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    ticket_id TEXT,
    details TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tickets_state ON tickets(state);
CREATE INDEX IF NOT EXISTS idx_actions_status ON pending_actions(status);
"""

UPDATABLE_FIELDS = {"category", "priority", "impact", "urgency", "assignment_group", "state", "resolution_notes"}


def now() -> str:
    return datetime.now(UTC).isoformat()


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: FastAPI may call from a thread pool; writes are short and serialized by SQLite.
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    # ---------- tickets ----------
    def next_ticket_id(self, prefix: str = "INC") -> str:
        row = self.conn.execute(
            "SELECT id FROM tickets WHERE id LIKE ? ORDER BY id DESC LIMIT 1", (f"{prefix}%",)).fetchone()
        number = int(row["id"][len(prefix):]) + 1 if row else 1001
        return f"{prefix}{number:07d}"

    def create_ticket(self, short_description: str, description: str, caller: str, actor: str,
                      source: str = "portal", ticket_type: str = "incident", parent_id: str | None = None,
                      **fields) -> dict:
        prefix = "CHG" if ticket_type == "change" else "INC"
        ticket_id = fields.pop("id", None) or self.next_ticket_id(prefix)
        ts = now()
        extra = {k: v for k, v in fields.items() if k in UPDATABLE_FIELDS}
        columns = ["id", "type", "short_description", "description", "caller", "source", "parent_id",
                   "created_at", "updated_at", *extra.keys()]
        values = [ticket_id, ticket_type, short_description, description, caller, source, parent_id, ts, ts,
                  *extra.values()]
        with self.conn:
            self.conn.execute(
                f"INSERT INTO tickets ({','.join(columns)}) VALUES ({','.join('?' * len(values))})", values)
            audit.append(self.conn, actor, "ticket.created", ticket_id,
                         {"type": ticket_type, "source": source, "short_description": short_description})
        return self.get_ticket(ticket_id)

    def get_ticket(self, ticket_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        return dict(row) if row else None

    def list_tickets(self, state: str | None = None, category: str | None = None,
                     query: str | None = None, limit: int = 20) -> list[dict]:
        sql, args = "SELECT * FROM tickets WHERE 1=1", []
        if state:
            sql += " AND state = ?"
            args.append(state)
        if category:
            sql += " AND category = ?"
            args.append(category)
        if query:
            sql += " AND (short_description LIKE ? OR description LIKE ?)"
            args += [f"%{query}%", f"%{query}%"]
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
        args.append(max(1, min(limit, 100)))
        return [dict(r) for r in self.conn.execute(sql, args)]

    def update_ticket(self, ticket_id: str, fields: dict, actor: str) -> dict:
        bad = set(fields) - UPDATABLE_FIELDS
        if bad:
            raise ValueError(f"fields not updatable: {sorted(bad)}")
        before = self.get_ticket(ticket_id)
        if before is None:
            raise KeyError(ticket_id)
        sets = ", ".join(f"{k} = ?" for k in fields) + ", updated_at = ?"
        with self.conn:
            self.conn.execute(f"UPDATE tickets SET {sets} WHERE id = ?", [*fields.values(), now(), ticket_id])
            audit.append(self.conn, actor, "ticket.updated", ticket_id,
                         {"before": {k: before[k] for k in fields}, "after": fields})
        return self.get_ticket(ticket_id)

    def add_work_note(self, ticket_id: str, note: str, author: str) -> None:
        if self.get_ticket(ticket_id) is None:
            raise KeyError(ticket_id)
        with self.conn:
            self.conn.execute("INSERT INTO work_notes (ticket_id, author, note, created_at) VALUES (?,?,?,?)",
                              (ticket_id, author, note, now()))
            audit.append(self.conn, author, "ticket.work_note_added", ticket_id, {"note": note[:200]})

    def work_notes(self, ticket_id: str) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT author, note, created_at FROM work_notes WHERE ticket_id = ? ORDER BY id", (ticket_id,))]

    # ---------- knowledge base ----------
    def upsert_kb(self, article: dict) -> None:
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO kb_articles (id, title, category, body) VALUES (?,?,?,?)",
                              (article["id"], article["title"], article["category"], article["body"]))

    def kb_articles(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM kb_articles ORDER BY id")]

    # ---------- pending actions (the approval queue) ----------
    def insert_action(self, **a) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO pending_actions (ticket_id, action, payload, rationale, proposed_by, risk, status,"
                " policy_notes, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (a["ticket_id"], a["action"], json.dumps(a["payload"]), a["rationale"], a["proposed_by"],
                 a["risk"], a["status"], json.dumps(a["policy_notes"]), now()))
        return cur.lastrowid

    def get_action(self, action_id: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,)).fetchone()
        return self._action(row) if row else None

    def list_actions(self, status: str | None = None, ticket_id: str | None = None, limit: int = 50) -> list[dict]:
        sql, args = "SELECT * FROM pending_actions WHERE 1=1", []
        if status:
            sql += " AND status = ?"
            args.append(status)
        if ticket_id:
            sql += " AND ticket_id = ?"
            args.append(ticket_id)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [self._action(r) for r in self.conn.execute(sql, args)]

    def set_action_status(self, action_id: int, status: str, decided_by: str | None = None,
                          result: dict | None = None) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE pending_actions SET status = ?, decided_by = COALESCE(?, decided_by),"
                " decided_at = CASE WHEN ? IS NULL THEN decided_at ELSE ? END, result = ? WHERE id = ?",
                (status, decided_by, decided_by, now(), json.dumps(result) if result else None, action_id))

    def count_recent_proposals(self, actor: str, since_iso: str) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM pending_actions WHERE proposed_by = ? AND created_at >= ?",
                                (actor, since_iso)).fetchone()
        return row[0]

    @staticmethod
    def _action(row) -> dict:
        d = dict(row)
        d["payload"] = json.loads(d["payload"])
        d["policy_notes"] = json.loads(d["policy_notes"])
        d["result"] = json.loads(d["result"]) if d.get("result") else None
        return d

    # ---------- metrics ----------
    def metrics(self) -> dict:
        q = self.conn.execute
        return {
            "tickets_by_state": {r[0]: r[1] for r in q("SELECT state, COUNT(*) FROM tickets GROUP BY state")},
            "tickets_by_category": {(r[0] or "untriaged"): r[1] for r in
                                    q("SELECT category, COUNT(*) FROM tickets GROUP BY category")},
            "actions_by_status": {r[0]: r[1] for r in
                                  q("SELECT status, COUNT(*) FROM pending_actions GROUP BY status")},
            "audit_entries": q("SELECT COUNT(*) FROM audit_log").fetchone()[0],
        }
