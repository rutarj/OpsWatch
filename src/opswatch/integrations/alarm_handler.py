"""What OpsWatch does with a verified CloudWatch alarm.

ALARM: open an incident (or add a note to the open one: no duplicate tickets per alarm).
OK:    note it on the open incident and PROPOSE a resolution. A human still approves;
       for P1 incidents the policy blocks agent resolution entirely.

The alarm comes from a verified AWS source, so category and priority are set directly
(machine data, not user-written text). Human-written tickets always go through proposals.
"""
from opswatch.app import OpsWatch
from opswatch.triage.rules import RulesTriager

ACTOR = "agent:sns-webhook"


def handle_alarm(ops: OpsWatch, alarm: dict) -> dict:
    name = alarm["alarm_name"]
    open_tickets = [t for t in ops.store.list_tickets(query=f"[ALARM] {name}", limit=20)
                    if t["state"] not in ("resolved", "closed") and t["short_description"] == f"[ALARM] {name}"]

    if alarm["state"] == "ALARM":
        if open_tickets:
            ops.store.add_work_note(open_tickets[0]["id"], f"Alarm fired again at {alarm['changed_at']}: "
                                                           f"{alarm['reason']}", "system:sns-webhook")
            return {"action": "noted_existing", "ticket_id": open_tickets[0]["id"]}
        description = (f"CloudWatch alarm ALARM in {alarm['region']}. Metric: {alarm['metric']}. "
                       f"Reason: {alarm['reason']} {alarm['description']}").strip()
        suggestion = RulesTriager().triage({"short_description": f"[ALARM] {name}", "description": description,
                                            "source": "monitoring"})
        ticket = ops.store.create_ticket(
            f"[ALARM] {name}", description, caller="aws-cloudwatch", actor="system:sns-webhook", source="monitoring",
            category="cloud_ops", assignment_group="Cloud Operations", priority=suggestion.priority,
            impact=suggestion.impact, urgency=suggestion.urgency, state="new")
        runbooks = ops.kb.search(f"{name} {alarm['metric']} {alarm['reason']}", k=2, category="cloud_ops",
                                 min_score=0.12)
        if runbooks:
            ops.store.add_work_note(ticket["id"], "Suggested runbooks: " + ", ".join(
                f"{r['id']} ({r['title']})" for r in runbooks), "system:sns-webhook")
        return {"action": "created", "ticket_id": ticket["id"], "priority": ticket["priority"]}

    if alarm["state"] == "OK" and open_tickets:
        ticket_id = open_tickets[0]["id"]
        ops.store.add_work_note(ticket_id, f"Alarm returned to OK at {alarm['changed_at']}.", "system:sns-webhook")
        result = ops.propose(ticket_id=ticket_id, action="resolve_ticket",
                             payload={"resolution_notes": f"CloudWatch alarm {name} returned to OK. "
                                                          "Verify root cause is fixed before approving."},
                             rationale="The alarm that opened this incident has cleared.", actor=ACTOR)
        return {"action": "proposed_resolution", "ticket_id": ticket_id, "proposal_status": result.status,
                "policy_reasons": result.reasons}

    return {"action": "ignored", "reason": f"state {alarm['state']} with {len(open_tickets)} open tickets"}
