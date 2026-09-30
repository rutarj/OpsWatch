"""Triage as a service: runs a triager, then applies guardrails and routing rules on top.

The triager only classifies. This layer decides whether a human must look at
the result, attaches knowledge base articles, and flags suspicious tickets.
"""
from pathlib import Path

from opswatch.config import Settings
from opswatch.guardrails import injection
from opswatch.kb import KnowledgeBase
from opswatch.triage.base import TriageResult, ticket_text
from opswatch.triage.llm import ClaudeTriager, HybridTriager
from opswatch.triage.ml import MLTriager
from opswatch.triage.rules import RulesTriager

ALWAYS_REVIEW_CATEGORIES = {"security"}


def run_triage(ticket: dict, triager, kb: KnowledgeBase | None, review_threshold: float) -> TriageResult:
    text = ticket_text(ticket)
    scan = injection.scan(text)
    result = triager.triage(ticket)

    if scan.suspicious:
        result.flags.append("possible_prompt_injection:" + ",".join(scan.matches))
    if kb is not None:
        result.suggested_kb = [a["id"] for a in kb.search(text, k=2, category=result.category)]

    reasons = []
    if result.confidence < review_threshold:
        reasons.append("low_confidence")
    if scan.suspicious or "llm_suspected_injection" in result.flags:
        reasons.append("suspicious_content")
    if result.category in ALWAYS_REVIEW_CATEGORIES:
        reasons.append("security_category")
    if result.priority == "P1":
        reasons.append("p1_priority")
    result.needs_human_review = bool(reasons)
    result.flags.extend(f"review:{r}" for r in reasons)
    return result


def load_or_train_ml(settings: Settings) -> MLTriager:
    model_file = settings.models_dir / "ml_triager.joblib"
    if model_file.exists():
        return MLTriager.load(settings.models_dir)
    from opswatch.seed import generate, load_jsonl

    train_path = settings.data_dir / "tickets_train.jsonl"
    if not train_path.exists():
        generate(settings.data_dir)
    model = MLTriager.train(load_jsonl(train_path))
    model.save(settings.models_dir)
    return model


def build_triager(name: str, settings: Settings, client=None):
    if name == "rules":
        return RulesTriager()
    if name == "ml":
        return load_or_train_ml(settings)
    if name == "llm":
        return ClaudeTriager(settings.anthropic_model, client=client)
    if name == "hybrid":
        # Rules go first: on the held-out eval they beat the ML model and cost nothing.
        # Only tickets below the confidence threshold are sent to Claude.
        return HybridTriager(RulesTriager(), ClaudeTriager(settings.anthropic_model, client=client),
                             settings.review_threshold)
    raise ValueError(f"unknown triager '{name}' (use rules, ml, llm or hybrid)")


def load_kb(data_dir: Path) -> KnowledgeBase:
    import json

    path = data_dir / "kb_articles.json"
    return KnowledgeBase(json.loads(path.read_text()) if path.exists() else [])
