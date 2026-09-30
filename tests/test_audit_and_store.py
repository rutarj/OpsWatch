from opswatch import audit
from opswatch.store import Store


def test_chain_verifies_after_normal_activity(ops):
    t = ops.store.list_tickets(limit=1)[0]
    ops.store.update_ticket(t["id"], {"state": "in_progress"}, actor="rutarj")
    ops.store.add_work_note(t["id"], "Checked cables.", "rutarj")
    result = audit.verify(ops.store.conn)
    assert result["ok"] and result["entries_checked"] >= 10


def test_editing_a_past_entry_is_detected(ops):
    ops.store.conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2")
    result = audit.verify(ops.store.conn)
    assert result == {"ok": False, "entries_checked": 1, "first_bad_seq": 2}


def test_deleting_an_entry_is_detected(ops):
    ops.store.conn.execute("DELETE FROM audit_log WHERE seq = 3")
    assert audit.verify(ops.store.conn)["ok"] is False


def test_empty_log_is_valid():
    assert audit.verify(Store(":memory:").conn)["ok"]


def test_ticket_ids_are_sequential_per_type():
    s = Store(":memory:")
    a = s.create_ticket("a", "b", "c", actor="x")
    b = s.create_ticket("a", "b", "c", actor="x")
    chg = s.create_ticket("a", "b", "c", actor="x", ticket_type="change")
    assert (a["id"], b["id"], chg["id"]) == ("INC0001001", "INC0001002", "CHG0001001")


def test_update_rejects_unknown_fields(ops):
    import pytest
    t = ops.store.list_tickets(limit=1)[0]
    with pytest.raises(ValueError):
        ops.store.update_ticket(t["id"], {"caller": "someone"}, actor="x")


def test_list_filters(ops):
    t = ops.store.list_tickets(limit=1)[0]
    ops.store.update_ticket(t["id"], {"category": "network", "state": "in_progress"}, actor="x")
    assert [r["id"] for r in ops.store.list_tickets(category="network")] == [t["id"]]
    assert all(r["state"] == "new" for r in ops.store.list_tickets(state="new"))
