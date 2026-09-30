import os
from pathlib import Path

import pytest

from opswatch.app import OpsWatch
from opswatch.config import PROJECT_ROOT, Settings
from opswatch.guardrails.policy import Policy
from opswatch.store import Store

os.environ.pop("ANTHROPIC_API_KEY", None)  # tests must never call the real API


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    from opswatch.seed import generate

    d = tmp_path_factory.mktemp("data")
    generate(d)
    return d


@pytest.fixture
def settings(tmp_path, data_dir) -> Settings:
    return Settings(db_path=Path(":memory:"), data_dir=data_dir, models_dir=tmp_path / "models",
                    reports_dir=tmp_path / "reports", policy_path=PROJECT_ROOT / "config" / "policy.toml",
                    api_key="test-key", sns_verify_signatures=True, triager="rules")


@pytest.fixture
def ops(settings) -> OpsWatch:
    o = OpsWatch.create(settings, triager_name="rules", store=Store(":memory:"))
    o.seed_open_tickets(8)
    return o


@pytest.fixture
def policy() -> Policy:
    return Policy.load(PROJECT_ROOT / "config" / "policy.toml")


def make_ticket(ops: OpsWatch, text: str = "My laptop won't power on. I can't work at all.", **fields) -> dict:
    return ops.store.create_ticket("Laptop issue", text, caller="Test User", actor="caller:test", **fields)
