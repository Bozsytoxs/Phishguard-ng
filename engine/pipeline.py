"""Public entry point used by the web app and the tests."""
from __future__ import annotations

from typing import Optional

from . import model, reputation, scorer

MAX_TEXT_LENGTH = 5000


def analyse_message(text: str, url: Optional[str] = None) -> dict:
    """Validate input, run rules + local model (+ optional URL reputation), return the analysis dict.

    Raises ValueError for empty or oversized input so the API can return a clear message.
    """
    text = (text or "").strip()
    url = (url or "").strip() or None
    if not text:
        raise ValueError("Please paste the message you want to check.")
    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError(f"That message is too long. Please keep it under {MAX_TEXT_LENGTH} characters.")

    extra = []
    if url:
        flagged = reputation.check_url_reputation(url)  # None unless an API key is set
        if flagged:
            extra.append(flagged)
    return scorer.analyse(text, url, proba_fn=model.predict_proba, extra_rules=extra)
