"""
Local ML signal: TF-IDF + Logistic Regression loaded from joblib files.

If the model files are missing or cannot be loaded (for example after a
scikit-learn upgrade) every function degrades gracefully and the app runs in
rules-only mode.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

MODEL_DIR = Path(os.environ.get("PHISHGUARD_MODEL_DIR", Path(__file__).resolve().parent.parent / "models"))
VECTORIZER_FILE = "vectorizer.joblib"
CLASSIFIER_FILE = "classifier.joblib"

_URL = re.compile(r"(?:https?://|www\.)\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+/\S*", re.I)
_AMOUNT = re.compile(r"(?:₦|ngn\s?|\bn)\s?\d[\d,.]*\s?(?:k|m)?\b|\b\d[\d,.]*\s?(?:k|naira|thousand|million)\b", re.I)
_NUMBER = re.compile(r"\d+")

_cache: dict = {}


def preprocess(text: str) -> str:
    """Normalise text for the model: lower-case, mask URLs, amounts and numbers.

    Used for BOTH training and prediction so the two always match.
    """
    text = (text or "").replace("’", "'").replace("‘", "'").lower()
    text = _URL.sub(" urltoken ", text)
    text = _AMOUNT.sub(" amounttoken ", text)
    text = _NUMBER.sub(" numtoken ", text)
    return re.sub(r"\s+", " ", text).strip()


def load_model(force: bool = False):
    """Return (vectorizer, classifier) or None if unavailable. Result is cached."""
    if not force and "bundle" in _cache:
        return _cache["bundle"]
    bundle = None
    vec_path, clf_path = MODEL_DIR / VECTORIZER_FILE, MODEL_DIR / CLASSIFIER_FILE
    if vec_path.exists() and clf_path.exists():
        try:
            import joblib
            bundle = (joblib.load(vec_path), joblib.load(clf_path))
        except Exception:  # corrupt file, version mismatch, joblib missing...
            bundle = None
    _cache["bundle"] = bundle
    return bundle


def is_available() -> bool:
    return load_model() is not None


def predict_proba(text: str):
    """Probability (0.0-1.0) that the text is phishing, or None in rules-only mode."""
    bundle = load_model()
    if bundle is None or not (text or "").strip():
        return None
    vectorizer, classifier = bundle
    try:
        features = vectorizer.transform([preprocess(text)])
        positive = list(classifier.classes_).index(1)
        return float(classifier.predict_proba(features)[0][positive])
    except Exception:
        return None
