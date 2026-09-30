import pytest

from opswatch import cli
from opswatch.demo import run_demo


@pytest.fixture
def env(tmp_path, data_dir, monkeypatch):
    monkeypatch.setenv("OPSWATCH_DB", str(tmp_path / "cli.db"))
    monkeypatch.setenv("OPSWATCH_DATA_DIR", str(data_dir))
    monkeypatch.setenv("OPSWATCH_MODELS_DIR", str(tmp_path / "models"))
    monkeypatch.setenv("OPSWATCH_REPORTS_DIR", str(tmp_path / "reports"))
    return tmp_path


def test_demo_runs_end_to_end(capsys, settings):
    run_demo(settings)
    out = capsys.readouterr().out
    assert "separation of duties" in out
    assert "agents may not resolve P1 incidents" in out
    assert "'ok': False" in out  # tamper detected at the end


def test_eval_command_with_gate(env, capsys):
    assert cli.main(["eval", "--triagers", "rules,ml", "--gate"]) == 0
    assert (env / "reports" / "EVALUATION.md").exists()


def test_train_command(env):
    assert cli.main(["train"]) == 0
    assert (env / "models" / "ml_triager.joblib").exists()


def test_approval_commands(env, capsys):
    from opswatch.app import OpsWatch
    from opswatch.config import get_settings

    ops = OpsWatch.create(get_settings(), triager_name="rules")
    ops.seed_open_tickets(3)
    t = ops.store.list_tickets(limit=1)[0]
    a = ops.propose(ticket_id=t["id"], action="add_work_note", payload={"note": "hi"}, rationale="r", actor="agent:x")
    b = ops.propose(ticket_id=t["id"], action="add_work_note", payload={"note": "yo"}, rationale="r", actor="agent:x")
    ops.store.conn.close()

    assert cli.main(["pending"]) == 0
    assert f"#{a.action_id}" in capsys.readouterr().out
    assert cli.main(["approve", str(a.action_id), "--by", "agent:x"]) == 2  # refused
    assert cli.main(["approve", str(a.action_id), "--by", "rutarj"]) == 0
    assert cli.main(["reject", str(b.action_id), "--by", "rutarj", "--reason", "dup"]) == 0
    assert cli.main(["audit-verify"]) == 0


def test_seed_command(env, capsys):
    assert cli.main(["seed"]) == 0
    assert "'train': 800" in capsys.readouterr().out
