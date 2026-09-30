"""Runtime settings, read from environment variables with safe defaults."""
import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    db_path: Path = field(default_factory=lambda: Path(os.getenv("OPSWATCH_DB", PROJECT_ROOT / "data" / "opswatch.db")))
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("OPSWATCH_DATA_DIR", PROJECT_ROOT / "data")))
    models_dir: Path = field(default_factory=lambda: Path(os.getenv("OPSWATCH_MODELS_DIR", PROJECT_ROOT / "models")))
    reports_dir: Path = field(default_factory=lambda: Path(os.getenv("OPSWATCH_REPORTS_DIR", PROJECT_ROOT / "reports")))
    policy_path: Path = field(
        default_factory=lambda: Path(os.getenv("OPSWATCH_POLICY", PROJECT_ROOT / "config" / "policy.toml")))
    # rules = offline default; hybrid = rules first, uncertain tickets escalate to Claude (needs ANTHROPIC_API_KEY)
    triager: str = field(default_factory=lambda: os.getenv("OPSWATCH_TRIAGER", "rules"))
    anthropic_model: str = field(default_factory=lambda: os.getenv("OPSWATCH_MODEL", "claude-haiku-4-5-20251001"))
    api_key: str | None = field(default_factory=lambda: os.getenv("OPSWATCH_API_KEY"))
    review_threshold: float = field(default_factory=lambda: float(os.getenv("OPSWATCH_REVIEW_THRESHOLD", "0.6")))
    sns_verify_signatures: bool = field(
        default_factory=lambda: os.getenv("OPSWATCH_SNS_VERIFY", "true").lower() == "true")


def get_settings() -> Settings:
    return Settings()
