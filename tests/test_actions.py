import pytest
from conftest import make_ticket

from opswatch.actions import ActionError


def _propose(ops, ticket_id, action="update_ticket", payload=None, actor="agent:mcp", rationale="because"):
    payload = payload if payload is not None else {"fields": {"category": "hardware", "priority": "P2"}}
    return ops.propose(ticket_id=ticket_id, action=action, payload=payload, rationale=rationale, actor=actor)


def test_proposal_waits_and_changes_nothing(ops):
    t = make_ticket(ops)
    r = _propose(ops, t["id"])
    assert r.status == "pending"
    assert ops.store.get_ticket(t["id"])["category"] is None


def test_approval_applies_update_and_sets_group(ops):
    t = make_ticket(ops)
    r = _propose(ops, t["id"])
    done = ops.approve(r.action_id, "rutarj")
    ticket = ops.store.get_ticket(t["id"])
    assert done["status"] == "executed"
    assert (ticket["category"], ticket["priority"], ticket["assignment_group"]) == ("hardware", "P2", "Desktop Support")


def test_self_approval_refused(ops):
    t = make_ticket(ops)
    r = _propose(ops, t["id"], actor="rutarj")
    with pytest.raises(ActionError, match="separation of duties"):
        ops.approve(r.action_id, "rutarj")


def test_agent_can_never_approve(ops):
    t = make_ticket(ops)
    r = _propose(ops, t["id"], actor="rutarj")
    with pytest.raises(ActionError, match="agents cannot approve"):
        ops.approve(r.action_id, "agent:mcp")


def test_high_risk_needs_senior_approver(ops):
    t = make_ticket(ops)
    r = _propose(ops, t["id"], action="resolve_ticket", payload={"resolution_notes": "Replaced the power adapter."})
    with pytest.raises(ActionError, match="high-risk"):
        ops.approve(r.action_id, "rutarj")
    ops.approve(r.action_id, "service-desk-lead")
    assert ops.store.get_ticket(t["id"])["state"] == "resolved"


def test_work_note_and_change_request_execute(ops):
    t = make_ticket(ops)
    note = _propose(ops, t["id"], action="add_work_note", payload={"note": "Checked the dock firmware."})
    ops.approve(note.action_id, "rutarj")
    assert ops.store.work_notes(t["id"])[0]["note"] == "Checked the dock firmware."
    chg = _propose(ops, t["id"], action="create_change",
                   payload={"summary": "Replace dock", "implementation_plan": "Swap unit",
                            "rollback_plan": "Reinstall old dock"})
    done = ops.approve(chg.action_id, "change-manager")
    change = ops.store.get_ticket(done["result"]["change_id"])
    assert change["type"] == "change" and change["parent_id"] == t["id"]


def test_reject(ops):
    t = make_ticket(ops)
    r = _propose(ops, t["id"])
    rejected = ops.reject(r.action_id, "rutarj", "wrong category")
    assert rejected["status"] == "rejected" and ops.store.get_ticket(t["id"])["category"] is None
    with pytest.raises(ActionError, match="not pending"):
        ops.approve(r.action_id, "rutarj")


def test_blocked_proposal_cannot_be_approved(ops):
    t = make_ticket(ops, priority="P1", category="network")
    r = _propose(ops, t["id"], action="resolve_ticket", payload={"resolution_notes": "Rebooted the core switch."})
    assert r.status == "blocked"
    with pytest.raises(ActionError, match="blocked"):
        ops.approve(r.action_id, "service-desk-lead")


@pytest.mark.parametrize("action, payload, match", [
    ("update_ticket", {"fields": {"category": "cooking"}}, "invalid category"),
    ("update_ticket", {"fields": {"priority": "P9"}}, "invalid priority"),
    ("update_ticket", {"fields": {"caller": "x"}}, "not allowed"),
    ("update_ticket", {"fields": {}}, "non-empty"),
    ("add_work_note", {"note": ""}, "note must be"),
    ("resolve_ticket", {"resolution_notes": "done"}, "10\\+"),
    ("create_change", {"summary": "x", "implementation_plan": "y"}, "rollback_plan"),
    ("drop_table", {}, "unknown action"),
])
def test_payload_validation(ops, action, payload, match):
    t = make_ticket(ops)
    with pytest.raises(ActionError, match=match):
        _propose(ops, t["id"], action=action, payload=payload)


def test_rationale_required(ops):
    t = make_ticket(ops)
    with pytest.raises(ActionError, match="rationale"):
        _propose(ops, t["id"], rationale="  ")


def test_unknown_ticket(ops):
    with pytest.raises(ActionError, match="not found"):
        _propose(ops, "INC9999999")


def test_every_step_is_audited(ops):
    t = make_ticket(ops)
    r = _propose(ops, t["id"])
    ops.approve(r.action_id, "rutarj")
    events = [row[0] for row in ops.store.conn.execute(
        "SELECT event FROM audit_log WHERE ticket_id = ? ORDER BY seq", (t["id"],))]
    assert events == ["ticket.created", "action.pending", "action.approved", "ticket.updated"]
