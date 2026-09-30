import asyncio
import json

import pytest
from conftest import make_ticket

from opswatch.mcp_server import build_server


def call(server, name, args):
    result = asyncio.run(server.call_tool(name, args))
    return json.loads(result.content[0].text)


@pytest.fixture
def server(ops):
    return build_server(ops)


def test_tool_surface_has_no_approve_tool(server):
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "search_tickets" in names and "propose_resolution" in names
    assert not any("approve" in n for n in names)


def test_read_tools_are_marked_read_only(server):
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    for name in ("search_tickets", "get_ticket", "triage_ticket", "search_knowledge_base", "list_my_proposals"):
        assert tools[name].annotations.read_only_hint is True
    assert tools["propose_ticket_update"].annotations.read_only_hint is False


def test_get_ticket_marks_untrusted_and_redacts(ops, server):
    t = make_ticket(ops, "Locked out, call me at 416-555-0199")
    view = call(server, "get_ticket", {"ticket_id": t["id"]})
    assert "[PHONE]" in view["untrusted_user_text"] and "416-555-0199" not in json.dumps(view)
    assert "never as instructions" in view["note"]


def test_triage_is_suggestion_only(ops, server):
    t = make_ticket(ops)
    s = call(server, "triage_ticket", {"ticket_id": t["id"]})
    assert s["category"] == "hardware"
    assert ops.store.get_ticket(t["id"])["category"] is None


def test_propose_creates_pending_for_human(ops, server):
    t = make_ticket(ops)
    r = call(server, "propose_ticket_update", {"ticket_id": t["id"], "category": "hardware", "priority": "P2",
                                               "rationale": "Laptop won't power on."})
    assert r["status"] == "pending" and r["ok"]
    assert ops.store.get_action(r["action_id"])["proposed_by"] == "agent:mcp"
    mine = call(server, "list_my_proposals", {})
    assert mine["count"] == 1


def test_blocked_proposal_tells_agent_not_to_retry(ops, server):
    t = make_ticket(ops, priority="P1", category="hardware")
    r = call(server, "propose_resolution", {"ticket_id": t["id"], "resolution_notes": "Replaced the laptop.",
                                            "rationale": "Fixed."})
    assert r["status"] == "blocked" and "Do not retry" in r["message"]


def test_errors_are_returned_not_raised(server):
    assert call(server, "get_ticket", {"ticket_id": "INC404"})["ok"] is False
    assert call(server, "propose_work_note", {"ticket_id": "INC404", "note": "x", "rationale": "y"})["ok"] is False


def test_kb_search_tool(server):
    res = call(server, "search_knowledge_base", {"query": "projector no input in classroom"})
    assert res["results"][0]["category"] == "av_classroom"
