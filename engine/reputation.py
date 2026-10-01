"""
OPTIONAL external URL reputation. Only runs when GOOGLE_SAFE_BROWSING_API_KEY
is set. Any failure (no internet, bad key, timeout) is silently ignored so the
core offline analysis is never affected.
"""
from __future__ import annotations

import json
import os
import urllib.request

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"


def check_url_reputation(url: str, timeout: float = 3.0):
    """Return a rule-shaped dict if Google Safe Browsing flags the URL, else None."""
    key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key or not url:
        return None
    body = {
        "client": {"clientId": "phishguard-ng", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        req = urllib.request.Request(
            ENDPOINT.format(key=key), data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return None
    if data.get("matches"):
        return {"id": "reputation_flag", "name": "Link reported as dangerous by Google Safe Browsing",
                "weight": 40, "evidence": url[:80]}
    return None
