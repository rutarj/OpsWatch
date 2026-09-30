"""Knowledge base search (TF-IDF + cosine similarity).

Small and dependency-light on purpose. For thousands of articles, swap this for
embeddings in a vector database; the function signature can stay the same.
"""
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class KnowledgeBase:
    def __init__(self, articles: list[dict]):
        self.articles = articles
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english", sublinear_tf=True)
        corpus = [f"{a['title']} {a['title']} {a['body']}" for a in articles]  # title counted twice: it's denser
        self.matrix = self.vectorizer.fit_transform(corpus) if articles else None

    def search(self, query: str, k: int = 3, category: str | None = None, min_score: float = 0.05) -> list[dict]:
        if not self.articles or not query.strip():
            return []
        scores = cosine_similarity(self.vectorizer.transform([query]), self.matrix)[0]
        ranked = sorted(zip(self.articles, scores, strict=True), key=lambda x: -x[1])
        results = []
        for article, score in ranked:
            if category and article["category"] != category:
                continue
            if score < min_score:
                break
            results.append({"id": article["id"], "title": article["title"], "category": article["category"],
                            "score": round(float(score), 3), "body": article["body"]})
            if len(results) == k:
                break
        return results
