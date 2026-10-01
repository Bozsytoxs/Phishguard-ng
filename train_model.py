"""
Train the local phishing classifier.

    python train_model.py

Reads data/scam_samples.csv (columns: text, label where 1 = scam, 0 = clean)
and writes models/vectorizer.joblib and models/classifier.joblib.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import make_pipeline

from engine.model import CLASSIFIER_FILE, MODEL_DIR, VECTORIZER_FILE, preprocess

DATA_PATH = Path(__file__).parent / "data" / "scam_samples.csv"


def load_samples(path: Path = DATA_PATH):
    """Return (texts, labels) from the CSV."""
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["text"].strip():
                texts.append(preprocess(row["text"]))
                labels.append(int(row["label"]))
    return texts, labels


def make_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1)


def make_classifier() -> LogisticRegression:
    return LogisticRegression(C=5.0, class_weight="balanced", max_iter=1000)


def main() -> int:
    texts, labels = load_samples()
    scams = sum(labels)
    print(f"Loaded {len(texts)} samples ({scams} scam, {len(texts) - scams} clean)")

    # Quick honesty check: cross-validated accuracy on this small dataset.
    folds = max(2, min(5, scams, len(labels) - scams))
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=42)
    scores = cross_val_score(make_pipeline(make_vectorizer(), make_classifier()), texts, labels, cv=cv)
    print(f"Cross-validated accuracy: {scores.mean():.0%} (+/- {scores.std():.0%}) on a small synthetic set")

    vectorizer, classifier = make_vectorizer(), make_classifier()
    classifier.fit(vectorizer.fit_transform(texts), labels)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(vectorizer, MODEL_DIR / VECTORIZER_FILE)
    joblib.dump(classifier, MODEL_DIR / CLASSIFIER_FILE)
    print(f"Saved {VECTORIZER_FILE} and {CLASSIFIER_FILE} to {MODEL_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
