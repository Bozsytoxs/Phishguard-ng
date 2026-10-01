"""PhishGuard NG detection engine (rules + local ML + hybrid scorer)."""
from .pipeline import analyse_message

__all__ = ["analyse_message"]
