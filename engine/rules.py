"""
Nigerian red-flag rule engine.

Each rule is a named category with a weight (0-100 scale contribution) and a
handful of regex patterns tuned to scams common on WhatsApp, SMS and email in
Nigeria. Everything here is a pure function so it is easy to unit test.

Public helpers
--------------
normalise_text(text)        -> lower-cased, quote-normalised text
find_red_flags(text, url)   -> list of matched rules (id, name, weight, evidence)
rules_score(matched)        -> 0-100 integer from matched rules
analyse_url(url)            -> list with at most one "suspicious_link" match
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Shared regex fragments
# --------------------------------------------------------------------------
# Naira amounts: ₦45,000 | N45000 | ngn 20k | 45k | 5 thousand | 2 million naira
AMT = (
    r"(?:(?:₦|ngn\s?|\bn)\s?\d[\d,.]*\s?(?:k|m)?\b"
    r"|\b\d[\d,.]*\s?(?:k|naira|thousand|million)\b)"
)

# "Do not share this code..." is a safety warning, not a request. Stripped
# before matching rules that flag requests for codes.
SAFETY_CLAUSE = re.compile(
    r"\b(?:please |kindly )?(?:do not|don't|dont|never)\s+"
    r"(?:share|give|send|disclose|reveal|forward)\b[^.\n]{0,60}",
    re.I,
)

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:xyz|top|click|work|live|icu|tk|ml|ga|cf|gq|buzz)\b[^\s]*",
    re.I,
)


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    weight: int
    patterns: tuple
    strip_safety: bool = False  # ignore "do not share..." warnings


def _c(*patterns: str) -> tuple:
    return tuple(re.compile(p, re.I) for p in patterns)


RULES: tuple = (
    Rule("new_number", "“New number” / lost phone story", 30, _c(
        r"\b(?:new|changed|another|different)\s+(?:phone\s+|mobile\s+|whatsapp\s+)?(?:number|line|no\b)",
        r"\bsave\s+(?:this|my)\s+(?:new\s+)?(?:number|no\b)",
        r"\b(?:lost|stolen|broke|broken|damaged|spoil(?:t|ed)|snatched)\s+(?:my\s+)?(?:phone|sim|handset)\b",
        r"\bmy\s+(?:phone|sim)\s+(?:was|got|has been|is)\s+(?:stolen|lost|spoil(?:t|ed)|damaged|snatched)",
        r"\busing\s+(?:a\s+)?(?:friend'?s|someone'?s)\s+phone",
    )),
    Rule("family_greeting", "Message posing as a family member", 10, _c(
        r"\b(?:hi|hello|hey)\s+(?:mum|mummy|mom|mama|dad|daddy|pa|ma|aunty|auntie|uncle|sis|bro|brother)\b"
        r"[^.\n]{0,30}\b(?:this is|it's|its|i am|i'm)\b",
        r"\b(?:it's me|its me|na me)\s+\w+\b",
    )),
    Rule("urgent_money", "Urgent request to send money", 30, _c(
        rf"\b(?:send|transfer|lend|borrow|pay|wire|remit|give)\b[^.\n]{{0,50}}?{AMT}",
        rf"{AMT}[^.\n]{{0,40}}\b(?:urgent(?:ly)?|now|today|asap|immediately|quick(?:ly)?)\b",
        r"\b(?:i|we)\s+(?:need|want)\b[^.\n]{0,25}\b(?:money|cash|credit|airtime|funds)\b",
        r"\bsend\b[^.\n]{0,30}\b(?:money|cash)\b",
        r"\babeg\s+send\b",
    )),
    Rule("gift_card", "Gift card request", 30, _c(
        r"\b(?:buy|purchase|get)\b[^.\n]{0,30}\bgift ?cards?\b",
        r"\b(?:itunes|google play|steam|amazon)\s+(?:gift\s+)?cards?\b",
    )),
    Rule("otp_request", "Asks for an OTP / verification code / PIN", 45, _c(
        r"\b(?:send|give|share|forward|tell|read|reply with|provide|confirm|return)\b[^.\n]{0,40}"
        r"\b(?:otp|code|pin|token|password|cvv|card number)\b",
        r"\bcode\s+(?:you|that|we)\s+(?:just\s+)?(?:received|got|sent)\b",
        r"\b(?:mistakenly|by mistake)\b[^.\n]{0,40}\bcode\b",
        r"\b(?:atm\s+)?pin\b[^.\n]{0,30}\b(?:to claim|to unblock|to verify|to confirm)\b",
    ), strip_safety=True),
    Rule("job_fee", "Job offer demanding payment", 40, _c(
        r"\b(?:registration|processing|application|training|form|interview|documentation|medical|uniform|admin(?:istrative)?)\s+fee\b",
        rf"\b(?:job|vacanc(?:y|ies)|recruit\w*|hiring|employment|appointment|shortlisted)\b[^.\n]{{0,100}}"
        rf"\b(?:pay|deposit|transfer|send)\b[^.\n]{{0,30}}{AMT}",
        r"\b(?:pay|deposit)\b[^.\n]{0,40}\bto\s+(?:secure|confirm|get|start)\b[^.\n]{0,30}\b(?:job|slot|position|appointment)\b",
    )),
    Rule("advance_fee", "Fee demanded before a prize, parcel or payout", 35, _c(
        r"\b(?:clearance|customs|delivery|courier|release|shipping|activation)\s+fee\b",
    )),
    Rule("isolation", "Tells you to keep it secret", 25, _c(
        r"\bdon'?t\s+(?:tell|say|let|inform)\b[^.\n]{0,30}\b(?:anyone|anybody|nobody|mum|mummy|mom|mama|dad|daddy|family|parents|husband|wife|bank|others)\b",
        r"\bdo not\s+(?:tell|discuss|inform)\b",
        r"\bkeep\s+(?:it|this)\b[^.\n]{0,20}\b(?:secret|between us|to yourself|private|confidential)\b",
        r"\bbetween us\b",
        r"\b(?:do not|don't)\s+(?:call|contact|use)\b[^.\n]{0,20}\bold\b",
    )),
    Rule("bank_impersonation", "Bank / CBN / BVN / NIN impersonation", 35, _c(
        r"\b(?:cbn|central bank of nigeria|nibss)\b[^.\n]{0,60}\b(?:notice|directive|order|require|compel|urge|alert|verify|update|link|block|suspend|deadline)\w*",
        r"\b(?:bvn|nin)\b[^.\n]{0,50}\b(?:update|verify|validat|link|confirm|block|suspend|flag|expire|send|reply|enter|provide|share)\w*",
        r"\b(?:update|verify|validat|link|confirm|send|provide|reply with|enter|share)\w*\b[^.\n]{0,40}\b(?:bvn|nin)\b",
        r"\b(?:account|wallet|card|atm)\b[^.\n]{0,40}\b(?:block|suspend|restrict|deactivat|lock|freez|frozen|hold|limit)\w*",
        r"\bkyc\b[^.\n]{0,40}\b(?:update|expire|incomplete|suspend|due)\w*",
    )),
    Rule("credential_phish", "Link asking you to log in or verify", 30, _c(
        r"\b(?:click|tap|open|follow)\b[^.\n]{0,30}\b(?:link|below|here)\b[^.\n]{0,50}"
        r"\b(?:verify|login|log in|sign in|update|confirm|claim|secure|unlock|register)\b",
        r"\bverify your (?:account|identity|email|password|details)\b",
        r"\byour password (?:will )?expire",
    )),
    Rule("invoice_fraud", "Changed bank details / invoice payment push", 35, _c(
        r"\b(?:changed|updated|new)\s+(?:our\s+|the\s+|my\s+)?(?:bank|account)\b",
        r"\b(?:bank|account)\s+(?:details|number|information)\b[^.\n]{0,30}\b(?:changed|updated|new)\b",
        r"\binvoice\b[^.\n]{0,80}\b(?:new|changed|updated)\b[^.\n]{0,20}\b(?:account|bank)\b",
        r"\bkindly\s+(?:remit|process payment|make payment)\b",
    )),
    Rule("prize_lottery", "Prize, grant or “free” reward claim", 35, _c(
        r"\byou\s+(?:have\s+|'ve\s+)?(?:just\s+)?won\b",
        r"\blucky\s+(?:draw|winner)\b",
        r"\bclaim\s+(?:your\s+)?(?:prize|reward|grant|gift|winnings)\b",
        r"\b(?:grant|palliative|scholarship)\b[^.\n]{0,60}\b(?:register|claim|click|pay|enter)\b",
        r"\bfree\s+(?:data|airtime|money)\b",
        r"\b(?:reward|bundle)\b[^.\n]{0,40}\bwaiting\b",
        r"\bcongratulations?\W+you\b",
    )),
    Rule("investment_scam", "Too-good-to-be-true investment", 35, _c(
        r"\bdouble\s+(?:your\s+)?money\b",
        r"\bguaranteed\s+(?:returns?|profit|roi)\b",
        r"\b\d{2,4}%\s*(?:profit|returns?|roi|guaranteed)\b",
        rf"\binvest\b[^.\n]{{0,40}}{AMT}[^.\n]{{0,60}}\b(?:receive|get|earn|return)\b",
        r"\b(?:crypto|forex|binary)\b[^.\n]{0,60}\b(?:group|signal|platform|invest|profit)\b",
        r"\bno risk\b",
        r"\bdaily\s+(?:roi|returns?|profit)\b",
    )),
    Rule("urgency_pressure", "Pressure to act immediately", 15, _c(
        r"\b(?:urgent(?:ly)?|asap|immediately|hurry|act now|last chance|final warning)\b",
        r"\bright now\b",
        r"\bwithin\s+\d+\s*(?:hours?|hrs?|mins?|minutes?)\b",
        r"\b(?:expires?|expiring)\b",
        r"\blimited\s+(?:slots?|vacanc(?:y|ies)|offer)\b",
        r"\blose access\b",
        r"\bbefore (?:end of day|friday|midnight)\b",
    )),
)

SUSPICIOUS_LINK = ("suspicious_link", "Suspicious link", 25)

# --------------------------------------------------------------------------
# URL heuristics
# --------------------------------------------------------------------------
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "ow.ly", "tiny.cc", "buff.ly"}
RISKY_TLDS = {"xyz", "top", "click", "work", "live", "icu", "tk", "ml", "ga", "cf", "gq", "buzz"}
# brand keyword -> official domains. A link using the keyword on any other domain is a lookalike.
BRANDS = {
    "gtbank": ("gtbank.com", "gtco.com"),
    "zenith": ("zenithbank.com",),
    "firstbank": ("firstbanknigeria.com",),
    "opay": ("opay.com", "opayweb.com", "opaycheckout.com"),
    "palmpay": ("palmpay.com",),
    "paystack": ("paystack.com", "paystack.co"),
    "flutterwave": ("flutterwave.com",),
    "cbn": ("cbn.gov.ng",),
    "nimc": ("nimc.gov.ng",),
    "whatsapp": ("whatsapp.com", "wa.me"),
    "paypal": ("paypal.com",),
    "mtn": ("mtn.ng", "mtn.com", "mtnonline.com"),
    "jumia": ("jumia.com.ng", "jumia.com"),
}


def normalise_text(text: str) -> str:
    """Lower-case, straighten curly quotes and collapse whitespace."""
    text = (text or "").replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    return re.sub(r"\s+", " ", text).strip().lower()


def extract_urls(text: str) -> list:
    """Return URLs/domains found inside free text (trailing punctuation removed)."""
    return [u.rstrip(".,);!?") for u in URL_RE.findall(text or "")]


def _host_of(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def url_findings(url: str) -> list:
    """Plain-language reasons a single URL looks risky (empty list = nothing odd)."""
    if not url or not url.strip():
        return []
    raw = url.strip()
    host = _host_of(raw)
    if not host:
        return ["The link could not be read properly"]
    reasons = []
    if host in SHORTENERS:
        reasons.append("Shortened link hides the real destination")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        reasons.append("Uses a raw IP address instead of a website name")
    if "@" in raw.split("//", 1)[-1].split("/", 1)[0]:
        reasons.append("Contains '@' which can disguise the real site")
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        reasons.append(f"Ends in .{tld}, often used for throw-away scam sites")
    if host.count("-") >= 2:
        reasons.append("Many hyphens in the domain name")
    if host.count(".") >= 4:
        reasons.append("Unusually many sub-domains")
    for brand, official in BRANDS.items():
        if brand in host and not any(host == d or host.endswith("." + d) for d in official):
            reasons.append(f"Looks like a “{brand}” link but is not their official website")
            break
    if raw.lower().startswith("http://"):
        reasons.append("Not using secure HTTPS")
    return reasons


def analyse_url(url: str) -> list:
    """Return a one-item list with a suspicious_link match, or [] if the URL looks fine."""
    reasons = url_findings(url)
    # Plain http alone is too weak to flag by itself.
    if not reasons or reasons == ["Not using secure HTTPS"]:
        return []
    weight = min(40, SUSPICIOUS_LINK[2] + 8 * (len(reasons) - 1))
    return [{
        "id": SUSPICIOUS_LINK[0], "name": SUSPICIOUS_LINK[1], "weight": weight,
        "evidence": url.strip()[:80], "details": reasons,
    }]


# --------------------------------------------------------------------------
# Matching + scoring
# --------------------------------------------------------------------------
def _first_match(patterns: tuple, text: str):
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m
    return None


def match_rules(text: str) -> list:
    """Run the text rules. Returns dicts: id, name, weight, evidence."""
    norm = normalise_text(text)
    stripped = SAFETY_CLAUSE.sub(" ", norm)
    matched = []
    for rule in RULES:
        haystack = stripped if rule.strip_safety else norm
        m = _first_match(rule.patterns, haystack)
        if m:
            matched.append({"id": rule.id, "name": rule.name, "weight": rule.weight,
                            "evidence": m.group(0).strip()[:90]})
    return matched


def apply_combos(matched: list) -> list:
    """Add bonus rules when classic scam patterns appear together."""
    ids = {m["id"] for m in matched}
    extra = []
    if {"new_number", "urgent_money"} <= ids:
        extra.append({"id": "combo_new_number_money", "name": "Classic “new number + send money” pattern",
                      "weight": 10, "evidence": "new number story and a money request together"})
    if len(ids - {"urgency_pressure", "family_greeting"}) >= 4:
        extra.append({"id": "multiple_red_flags", "name": "Several different red flags in one message",
                      "weight": 10, "evidence": f"{len(ids)} categories matched"})
    return matched + extra


def find_red_flags(text: str, url: str | None = None) -> list:
    """All red flags for a message (+ any URL inside it or supplied separately), heaviest first."""
    matched = match_rules(text)
    urls = ([url] if url else []) + extract_urls(text)
    best = None
    for u in urls:
        hits = analyse_url(u)
        if hits and (best is None or hits[0]["weight"] > best["weight"]):
            best = hits[0]
    if best:
        matched.append(best)
    matched = apply_combos(matched)
    return sorted(matched, key=lambda m: m["weight"], reverse=True)


def rules_score(matched: list) -> int:
    """Sum of matched weights, capped at 100."""
    return min(100, sum(m["weight"] for m in matched))
