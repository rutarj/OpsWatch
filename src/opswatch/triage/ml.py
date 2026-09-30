"""Baseline 2: classic ML (TF-IDF + logistic regression). Cheap, fast, runs offline.

Two small models: one predicts category, one predicts priority. Probabilities
give a real confidence score, which drives the human-review threshold.
"""
import time
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from opswatch.taxonomy import group_for
from opswatch.triage.base import TriageResult, ticket_text


def _pipeline() -> Pipeline:
    # Word n-grams capture phrases ("locked out"); character n-grams survive typos ("pasword").
    features = FeatureUnion([
        ("words", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])
    return Pipeline([("features", features),
                     ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced"))])


class MLTriager:
    name = "ml"

    def __init__(self, category_model: Pipeline, priority_model: Pipeline):
        self.category_model = category_model
        self.priority_model = priority_model

    @classmethod
    def train(cls, rows: list[dict]) -> "MLTriager":
        texts = [ticket_text(r) for r in rows]
        cat_model = _pipeline().fit(texts, [r["label"]["category"] for r in rows])
        pri_model = _pipeline().fit(texts, [r["label"]["priority"] for r in rows])
        return cls(cat_model, pri_model)

    def save(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "ml_triager.joblib"
        joblib.dump({"category": self.category_model, "priority": self.priority_model}, path)
        return path

    @classmethod
    def load(cls, directory: Path) -> "MLTriager":
        # Only load model files this project created. joblib/pickle files can run code when loaded.
        bundle = joblib.load(directory / "ml_triager.joblib")
        return cls(bundle["category"], bundle["priority"])

    def triage(self, ticket: dict) -> TriageResult:
        start = time.perf_counter()
        text = ticket_text(ticket)
        cat_probs = self.category_model.predict_proba([text])[0]
        pri_probs = self.priority_model.predict_proba([text])[0]
        ci, pi = cat_probs.argmax(), pri_probs.argmax()
        category = self.category_model.classes_[ci]
        top3 = sorted(zip(self.category_model.classes_, cat_probs, strict=True), key=lambda x: -x[1])[:3]
        return TriageResult(
            category=category, priority=self.priority_model.classes_[pi], assignment_group=group_for(category),
            confidence=round(float(cat_probs[ci]), 3), method=self.name,
            rationale="top categories: " + ", ".join(f"{c} {p:.2f}" for c, p in top3),
            latency_ms=round((time.perf_counter() - start) * 1000, 3),
        )
