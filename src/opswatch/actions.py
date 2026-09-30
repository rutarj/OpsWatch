"""The approval workflow: propose -> (policy check) -> pending -> human approves -> execute.

This mirrors how change management works in a bank: anyone (including the AI)
can raise a request, but it only takes effect after an authorized human signs off,
and every step is written to the audit log.
"""
from dataclasses import dataclass

from opswatch import audit
from opswatch.guardrails import injection
from opswatch.guardrails.policy import Policy, one_hour_ago
from opswatch.store import Store
from opswatch.taxonomy import TICKET_STATES, Category, Priority, group_for


class ActionError(Exception):
    pass


@dataclass
class ProposalResult:
    action_id: int
    status: str
    risk: str
    reasons: list[str]


def _validate_payload(action: str, payload: dict, max_note: int) -> dict:
    """Strict schemas for every action. The LLM's output is never trusted as-is (OWASP LLM05)."""
    if action == "update_ticket":
        fields = payload.get("fields")
        if not isinstance(fields, dict) or not fields:
            raise ActionError("update_ticket needs a non-empty 'fields' object")
        allowed = {"category", "priority", "assignment_group", "state"}
        bad = set(fields) - allowed
        if bad:
            raise ActionError(f"fields not allowed: {sorted(bad)}")
        if "category" in fields and fields["category"] not in {c.value for c in Category}:
            raise ActionError("invalid category")
        if "priority" in fields and fields["priority"] not in {p.value for p in Priority}:
            raise ActionError("invalid priority")
        if "state" in fields and fields["state"] not in TICKET_STATES:
            raise ActionError("invalid state")
        if "category" in fields and "assignment_group" not in fields:
            fields = {**fields, "assignment_group": group_for(fields["category"])}
        return {"fields": fields}
    if action == "add_work_note":
        note = str(payload.get("note", "")).strip()
        if not note or len(note) > max_note:
            raise ActionError(f"note must be 1-{max_note} characters")
        return {"note": note}
    if action == "resolve_ticket":
        notes = str(payload.get("resolution_notes", "")).strip()
        if len(notes) < 10:
            raise ActionError("resolution_notes must explain the fix (10+ characters)")
        return {"resolution_notes": notes[:max_note]}
    if action == "create_change":
        summary = str(payload.get("summary", "")).strip()
        plan = str(payload.get("implementation_plan", "")).strip()
        rollback = str(payload.get("rollback_plan", "")).strip()
        if not (summary and plan and rollback):
            raise ActionError("create_change needs summary, implementation_plan and rollback_plan")
        return {"summary": summary[:200], "implementation_plan": plan[:max_note], "rollback_plan": rollback[:max_note]}
    raise ActionError(f"unknown action '{action}'")


def propose(store: Store, policy: Policy, *, ticket_id: str, action: str, payload: dict,
            rationale: str, actor: str) -> ProposalResult:
    ticket = store.get_ticket(ticket_id)
    if ticket is None:
        raise ActionError(f"ticket {ticket_id} not found")
    if not rationale or not rationale.strip():
        raise ActionError("a rationale is required so the approver knows why")

    clean = _validate_payload(action, payload, policy.raw["limits"]["max_note_length"])
    suspicious = injection.scan(f"{ticket['short_description']}\n{ticket['description']}").suspicious
    decision = policy.evaluate(
        action=action, actor=actor, ticket=ticket, payload=clean, suspicious=suspicious,
        recent_proposals=store.count_recent_proposals(actor, one_hour_ago()),
        open_for_ticket=len(store.list_actions(status="pending", ticket_id=ticket_id)),
    )

    if not decision.allowed:
        status = "blocked"
    elif decision.requires_approval:
        status = "pending"
    else:
        status = "approved"

    action_id = store.insert_action(ticket_id=ticket_id, action=action, payload=clean, rationale=rationale.strip(),
                                    proposed_by=actor, risk=decision.risk, status=status,
                                    policy_notes=decision.reasons)
    with store.conn:
        audit.append(store.conn, actor, f"action.{status}", ticket_id,
                     {"action_id": action_id, "action": action, "risk": decision.risk, "reasons": decision.reasons})

    if status == "approved":  # only reachable when policy auto-approves low risk
        _execute(store, store.get_action(action_id), approver="policy:auto")
        status = "executed"
    return ProposalResult(action_id, status, decision.risk, decision.reasons)


def approve(store: Store, policy: Policy, action_id: int, approver: str) -> dict:
    action = _pending(store, action_id)
    if approver == action["proposed_by"]:
        raise ActionError("the proposer cannot approve their own action (separation of duties)")
    ok, why = policy.can_approve(approver, action["risk"])
    if not ok:
        raise ActionError(why)
    store.set_action_status(action_id, "approved", decided_by=approver)
    with store.conn:
        audit.append(store.conn, approver, "action.approved", action["ticket_id"], {"action_id": action_id})
    return _execute(store, store.get_action(action_id), approver)


def reject(store: Store, policy: Policy, action_id: int, approver: str, reason: str) -> dict:
    action = _pending(store, action_id)
    ok, why = policy.can_approve(approver, "low")  # any valid human approver may reject
    if not ok:
        raise ActionError(why)
    store.set_action_status(action_id, "rejected", decided_by=approver, result={"reason": reason})
    with store.conn:
        audit.append(store.conn, approver, "action.rejected", action["ticket_id"],
                     {"action_id": action_id, "reason": reason})
    return store.get_action(action_id)


def _pending(store: Store, action_id: int) -> dict:
    action = store.get_action(action_id)
    if action is None:
        raise ActionError(f"action {action_id} not found")
    if action["status"] != "pending":
        raise ActionError(f"action {action_id} is '{action['status']}', not pending")
    return action


def _execute(store: Store, action: dict, approver: str) -> dict:
    """Apply an approved action. The executor is recorded as the human approver, not the agent."""
    kind, ticket_id, payload = action["action"], action["ticket_id"], action["payload"]
    actor = f"{approver} (on behalf of {action['proposed_by']})"
    if kind == "update_ticket":
        store.update_ticket(ticket_id, payload["fields"], actor)
        result = {"updated": payload["fields"]}
    elif kind == "add_work_note":
        store.add_work_note(ticket_id, payload["note"], actor)
        result = {"note_added": True}
    elif kind == "resolve_ticket":
        store.update_ticket(ticket_id, {"state": "resolved", "resolution_notes": payload["resolution_notes"]}, actor)
        result = {"resolved": True}
    elif kind == "create_change":
        change = store.create_ticket(
            short_description=payload["summary"],
            description=f"Implementation plan:\n{payload['implementation_plan']}\n\nRollback plan:\n"
                        f"{payload['rollback_plan']}",
            caller=approver, actor=actor, source="opswatch", ticket_type="change", parent_id=ticket_id,
            state="new")
        result = {"change_id": change["id"]}
    else:
        raise ActionError(f"cannot execute '{kind}'")
    store.set_action_status(action["id"], "executed", result=result)
    return store.get_action(action["id"])
