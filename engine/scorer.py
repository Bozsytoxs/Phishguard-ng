"""
Hybrid scorer: combines rule matches with the optional ML probability.

* Rules drive the score and the explanation.
* The AI signal nudges the score up when rules AND model agree, and can lift a
  message with weak rules into Medium, but it can never reach High on its own.
"""
from __future__ import annotations

from typing import Callable, Optional

from . import rules as rules_mod

DISCLAIMER = "PhishGuard NG gives guidance, not certainty. When in doubt, verify through an official channel."

LEVEL_LABELS = {
    "Critical": "Critical risk: very likely a scam",
    "High": "High risk: probably a scam",
    "Medium": "Medium risk: be careful",
    "Low": "Low risk: no strong warning signs",
}

# Advice for each matched rule id (first = most important).
ADVICE = {
    "new_number": ["Call the old number you already know, or ask a family member who can confirm, before doing anything. Do not trust a “new number” message on its own."],
    "family_greeting": ["Ask a question only the real person could answer (a nickname, last visit) or make a voice/video call."],
    "combo_new_number_money": ["This is the classic “Hi Mum, new number” scam. Do not send money until you have spoken to the real person."],
    "urgent_money": ["Do not transfer money because of a message. Pause, then confirm by phone or in person."],
    "gift_card": ["Never buy gift cards for someone who messages you, even if it looks like your boss or a relative."],
    "otp_request": ["Never share an OTP, PIN, password or verification code with anyone. Banks and apps never ask for it."],
    "job_fee": ["Real employers do not charge for registration, forms, training or interviews. Do not pay to get a job."],
    "advance_fee": ["Do not pay “clearance”, “delivery” or “release” fees to claim a prize or parcel. That is how the scam works."],
    "isolation": ["Tell someone you trust. Scammers say “don’t tell anyone” so nobody can warn you."],
    "bank_impersonation": ["Do not reply. Contact your bank using the number on your card or the official app. CBN and banks never ask for BVN, NIN or PIN by message."],
    "credential_phish": ["Do not tap the link or log in through it. Type the official website address yourself or use the official app."],
    "suspicious_link": ["Do not open the link. Check the website name letter by letter, official sites rarely use odd endings or extra hyphens."],
    "reputation_flag": ["The link was reported as dangerous. Close it and do not enter any details."],
    "invoice_fraud": ["Verify any change of bank details by calling the supplier on a number you already have, never the one in the message."],
    "prize_lottery": ["If you did not enter a contest you cannot win it. Real prizes never need you to pay first."],
    "investment_scam": ["No legitimate investment guarantees big profits or doubles your money. Do not invest through chat groups or unknown platforms."],
    "urgency_pressure": ["Slow down. Pressure to act “now” is a tactic to stop you from thinking."],
    "multiple_red_flags": ["Several warning signs together make this very unlikely to be genuine. Delete or ignore it."],
}

GENERAL_ADVICE = {
    "Critical": "If you already sent money or a code: call your bank immediately, then report to the NCC (toll-free 622) or the police.",
    "High": "If you already sent money or a code: call your bank immediately and report the number or sender.",
}

LOW_ADVICE = [
    "No strong red flags were found, but no tool is perfect. If the message asks for money, codes or personal details, pause and verify first.",
    "Confirm the sender using a number or website you already trust.",
    "When in doubt, ask a family member or colleague before acting.",
]


def level_for(score: int) -> str:
    """Critical >= 75, High >= 55, Medium >= 30, else Low."""
    if score >= 75:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def combine(rule_points: int, ai_probability: Optional[float]) -> int:
    """Blend rule points (0-100) and AI probability (0-1) into the final 0-100 score."""
    if ai_probability is None:
        return int(round(min(100, rule_points)))
    ai_points = ai_probability * 100
    if rule_points >= 30:
        # Rules found real evidence: the model only confirms or slightly boosts.
        score = rule_points + ai_probability * 15
        if ai_probability < 0.2:
            score -= 5  # model sees nothing suspicious: small step back
    else:
        # Weak rules: model can lift a message, capped below "High".
        score = min(54, rule_points * 0.5 + ai_points * 0.55)
    return int(round(max(0, min(100, score))))


def build_advice(level: str, matched: list) -> list:
    """Numbered-list friendly advice specific to the matched rules."""
    if level == "Low":
        return list(LOW_ADVICE)
    advice = ["Do not click, reply or send anything yet."]
    for rule in matched:  # already heaviest-first
        for line in ADVICE.get(rule["id"], [])[:1]:
            if line not in advice:
                advice.append(line)
    if level in GENERAL_ADVICE:
        advice.append(GENERAL_ADVICE[level])
    else:
        advice.append("If unsure, check with someone you trust or the official source before acting.")
    return advice[:7]


def build_summary(level: str, matched: list, ai_probability: Optional[float]) -> str:
    """One plain-language explanation of why the score was given."""
    if not matched:
        base = "We did not find any of the common Nigerian scam patterns in this message."
    else:
        names = [m["name"].lower() for m in matched if not m["id"].startswith(("combo_", "multiple_"))][:3]
        base = "This message matches known scam patterns: " + ", ".join(names) + "."
    if ai_probability is not None:
        base += f" Our pattern model also rates it {round(ai_probability * 100)}% similar to known scams."
    return base


def analyse(text: str, url: Optional[str] = None,
            proba_fn: Optional[Callable[[str], Optional[float]]] = None,
            extra_rules: Optional[list] = None) -> dict:
    """Score a message. Pure: pass `proba_fn` to inject the ML model (or None for rules-only)."""
    matched = rules_mod.find_red_flags(text, url)
    if extra_rules:
        matched = sorted(matched + list(extra_rules), key=lambda m: m["weight"], reverse=True)
    rule_points = rules_mod.rules_score(matched)

    ai_probability = None
    if proba_fn is not None:
        combined_text = f"{text}\n{url}" if url else text
        ai_probability = proba_fn(combined_text)
        if ai_probability is not None:
            ai_probability = round(float(ai_probability), 3)

    score = combine(rule_points, ai_probability)
    level = level_for(score)
    return {
        "risk_level": level,
        "level_label": LEVEL_LABELS[level],
        "score": score,
        "matched_rules": matched,
        "ai_probability": ai_probability,
        "advice": build_advice(level, matched),
        "summary": build_summary(level, matched, ai_probability),
        "engine_mode": "hybrid" if ai_probability is not None else "rules-only",
        "disclaimer": DISCLAIMER,
    }
