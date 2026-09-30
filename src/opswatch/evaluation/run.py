"""Offline evaluation on the held-out test split. Every number in the README comes from here.

What's measured:
- category accuracy and macro-F1 (macro = every category counts equally, so rare ones matter)
- priority accuracy, and "within one level" (P2 predicted as P3 is less bad than P1 as P4)
- routing accuracy (assignment group), which is what actually matters to the service desk
- selective accuracy: if only confident predictions are auto-accepted, how many tickets
  skip human review (coverage) and how accurate are those?
- latency, and tokens/cost when the LLM is evaluated
- prompt-injection detector precision/recall on a separate labeled set
"""
import json
import os
import statistics
import time
import tomllib
from pathlib import Path

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score

from opswatch.config import PROJECT_ROOT, Settings
from opswatch.guardrails import injection
from opswatch.seed import generate, load_jsonl
from opswatch.taxonomy import Category
from opswatch.triage.service import build_triager

PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]


def _pct(x: float) -> float:
    return round(100 * x, 1)


def evaluate_triager(triager, rows: list[dict], limit: int | None = None) -> dict:
    rows = rows[:limit] if limit else rows
    preds, latencies, in_tok, out_tok = [], [], 0, 0
    for row in rows:
        start = time.perf_counter()
        result = triager.triage(row)
        latencies.append((time.perf_counter() - start) * 1000)
        in_tok += result.input_tokens
        out_tok += result.output_tokens
        preds.append(result)

    y_cat = [r["label"]["category"] for r in rows]
    p_cat = [p.category for p in preds]
    y_pri = [r["label"]["priority"] for r in rows]
    p_pri = [p.priority for p in preds]
    y_grp = [r["label"]["assignment_group"] for r in rows]
    p_grp = [p.assignment_group for p in preds]
    within_one = sum(abs(PRIORITY_RANK[a] - PRIORITY_RANK[b]) <= 1 for a, b in zip(y_pri, p_pri, strict=True))
    labels = [c.value for c in Category]

    selective = []
    for t in THRESHOLDS:
        kept = [(y, p.category) for y, p in zip(y_cat, preds, strict=True) if p.confidence >= t]
        selective.append({"threshold": t, "coverage_pct": _pct(len(kept) / len(rows)),
                          "accuracy_pct": _pct(sum(y == p for y, p in kept) / len(kept)) if kept else None})

    fallbacks = sum("fallback" in p.method for p in preds)
    return {
        "n": len(rows),
        "category_accuracy_pct": _pct(accuracy_score(y_cat, p_cat)),
        "category_macro_f1": round(f1_score(y_cat, p_cat, average="macro", labels=labels, zero_division=0), 3),
        "priority_accuracy_pct": _pct(accuracy_score(y_pri, p_pri)),
        "priority_within_one_pct": _pct(within_one / len(rows)),
        "routing_accuracy_pct": _pct(accuracy_score(y_grp, p_grp)),
        "latency_ms": {"p50": round(statistics.median(latencies), 2),
                       "p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 2)},
        "tokens": {"input": in_tok, "output": out_tok},
        "fallbacks": fallbacks,
        "selective": selective,
        "per_category": {k: {"precision": round(v["precision"], 3), "recall": round(v["recall"], 3),
                             "f1": round(v["f1-score"], 3), "support": int(v["support"])}
                         for k, v in classification_report(y_cat, p_cat, labels=labels, output_dict=True,
                                                           zero_division=0).items() if k in labels},
        "confusion": {"labels": labels, "matrix": confusion_matrix(y_cat, p_cat, labels=labels).tolist()},
    }


def evaluate_injection(rows: list[dict]) -> dict:
    tp = fp = fn = tn = 0
    false_positives, misses = [], []
    for row in rows:
        flagged = injection.scan(row["text"]).suspicious
        if flagged and row["is_injection"]:
            tp += 1
        elif flagged:
            fp += 1
            false_positives.append(row["text"][-120:])
        elif row["is_injection"]:
            fn += 1
            misses.append(row["text"][-120:])
        else:
            tn += 1
    return {"n": len(rows), "true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
            "false_positive_examples": false_positives, "missed_examples": misses}


def llm_cost(model: str, tokens: dict) -> dict | None:
    pricing = tomllib.loads((PROJECT_ROOT / "config" / "pricing.toml").read_text())
    rates = pricing.get("models", {}).get(model)
    if not rates or not tokens["input"]:
        return None
    cost = tokens["input"] / 1e6 * rates["input_per_mtok"] + tokens["output"] / 1e6 * rates["output_per_mtok"]
    return {"usd_total": round(cost, 4), "pricing_verified_on": pricing["verified_on"]}


def run(settings: Settings, triagers: list[str], llm_limit: int = 60) -> dict:
    if not (settings.data_dir / "tickets_test.jsonl").exists():
        generate(settings.data_dir)
    test = load_jsonl(settings.data_dir / "tickets_test.jsonl")
    results = {"dataset": {"test_tickets": len(test), "note": "synthetic, held-out templates and phrasings"},
               "triagers": {}}
    for name in triagers:
        if name in ("llm", "hybrid") and not os.getenv("ANTHROPIC_API_KEY"):
            results["triagers"][name] = {"skipped": "ANTHROPIC_API_KEY not set"}
            continue
        triager = build_triager(name, settings)
        limit = llm_limit if name in ("llm", "hybrid") else None
        metrics = evaluate_triager(triager, test, limit)
        if name in ("llm", "hybrid"):
            metrics["model"] = settings.anthropic_model
            metrics["cost"] = llm_cost(settings.anthropic_model, metrics["tokens"])
        results["triagers"][name] = metrics
    results["injection_detector"] = evaluate_injection(load_jsonl(settings.data_dir / "injection_eval.jsonl"))
    return results


def check_gate(results: dict, gate_path: Path) -> list[str]:
    gate = tomllib.loads(gate_path.read_text())
    failures = []
    for name in ("ml", "rules"):
        m = results["triagers"].get(name, {})
        if "category_accuracy_pct" not in m:
            continue
        if m["category_accuracy_pct"] < 100 * gate[name]["min_category_accuracy"]:
            failures.append(f"{name} category accuracy {m['category_accuracy_pct']}% below gate")
        min_pri = gate[name].get("min_priority_accuracy")
        if min_pri and m["priority_accuracy_pct"] < 100 * min_pri:
            failures.append(f"{name} priority accuracy {m['priority_accuracy_pct']}% below gate")
    inj = results["injection_detector"]
    if (inj["recall"] or 0) < gate["injection_detector"]["min_recall"]:
        failures.append(f"injection recall {inj['recall']} below gate")
    if (inj["false_positive_rate"] or 0) > gate["injection_detector"]["max_false_positive_rate"]:
        failures.append(f"injection false-positive rate {inj['false_positive_rate']} above gate")
    return failures


def write_reports(results: dict, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "eval_results.json").write_text(json.dumps(results, indent=2))
    md = ["# Evaluation report", "",
          "Generated by `opswatch eval`. Do not edit by hand; rerun to refresh.", "",
          f"Test set: {results['dataset']['test_tickets']} tickets, {results['dataset']['note']}.", "",
          "## Triage accuracy", "",
          "| Triager | Category acc. | Macro-F1 | Priority acc. | Priority within 1 | Routing acc. | p50 latency |",
          "|---|---|---|---|---|---|---|"]
    for name, m in results["triagers"].items():
        if "skipped" in m:
            md.append(f"| {name} | skipped: {m['skipped']} | | | | | |")
            continue
        md.append(f"| {name} | {m['category_accuracy_pct']}% | {m['category_macro_f1']} | "
                  f"{m['priority_accuracy_pct']}% | {m['priority_within_one_pct']}% | {m['routing_accuracy_pct']}% | "
                  f"{m['latency_ms']['p50']} ms |")
    for name, m in results["triagers"].items():
        if "selective" not in m:
            continue
        md += ["", f"## Human-review threshold: {name}", "",
               "Tickets at or above the confidence threshold are auto-suggested; the rest go to a person.", "",
               "| Threshold | Auto-handled (coverage) | Accuracy on auto-handled |", "|---|---|---|"]
        md += [f"| {s['threshold']} | {s['coverage_pct']}% | {s['accuracy_pct']}% |" for s in m["selective"]]
        md += ["", f"### Per-category ({name})", "", "| Category | Precision | Recall | F1 | Support |",
               "|---|---|---|---|---|"]
        md += [f"| {c} | {v['precision']} | {v['recall']} | {v['f1']} | {v['support']} |"
               for c, v in m["per_category"].items()]
        if m.get("cost"):
            md += ["", f"LLM tokens: {m['tokens']}. Estimated cost: ${m['cost']['usd_total']} "
                       f"(pricing verified: {m['cost']['pricing_verified_on']})."]
    inj = results["injection_detector"]
    md += ["", "## Prompt-injection detector", "",
           f"{inj['n']} labeled examples. Precision {inj['precision']}, recall {inj['recall']}, "
           f"false-positive rate {inj['false_positive_rate']}.", ""]
    if inj["false_positive_examples"]:
        md += ["False positives (benign text flagged):", ""] + [f"- `...{t}`" for t in inj["false_positive_examples"]]
    if inj["missed_examples"]:
        md += ["", "Missed injections:", ""] + [f"- `...{t}`" for t in inj["missed_examples"]]
    md += ["", "The detector is a first layer only. Even a missed injection can at most create a proposal, "
               "because the agent cannot approve anything."]
    path = reports_dir / "EVALUATION.md"
    path.write_text("\n".join(md) + "\n")
    return path
