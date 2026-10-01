"""
Tests for the rule engine, scorer and pipeline.

Run with:  python -m pytest -q        (or)        python -m tests.test_engine
Tests that need the trained model skip themselves if train_model.py has not been run.
"""
import csv
from pathlib import Path

from engine import model, rules, scorer
from engine.pipeline import analyse_message

HI_MUM = "Hi Mum, this is my new number. My old phone got stolen. Please save it and send ₦45,000 urgently, I will explain later."
FRIENDLY = "Hey! Are we still meeting at 4pm for the group project? Library second floor."
REAL_OTP = "Your GTBank OTP is 482910. Do not share this code with anyone, including bank staff."


def ids(text, url=None):
    return {m["id"] for m in rules.find_red_flags(text, url)}


# ---- rules -----------------------------------------------------------------
def test_new_number_and_money_rules():
    found = ids(HI_MUM)
    assert {"new_number", "urgent_money", "urgency_pressure", "combo_new_number_money"} <= found


def test_each_rule_category_fires_on_known_scams():
    samples = {
        "urgent_money": "Please send ₦20,000 to this account now",
        "otp_request": "Please forward the OTP you received, I need it to verify my number.",
        "job_fee": "You are shortlisted. Pay ₦15,000 registration fee to secure your slot.",
        "isolation": "Don't tell anyone about this, keep it between us.",
        "bank_impersonation": "CBN notice: your BVN must be updated or your account will be suspended.",
        "new_number": "Hello, I changed my number, save this new number.",
        "invoice_fraud": "Our bank details have changed. Kindly remit payment to the new account.",
        "prize_lottery": "You have won ₦5,000,000 in the lucky draw.",
        "investment_scam": "Double your money in 48 hours, guaranteed returns.",
    }
    for rule_id, text in samples.items():
        assert rule_id in ids(text), f"{rule_id} did not match: {text}"


def test_real_otp_notice_is_not_an_otp_request():
    assert "otp_request" not in ids(REAL_OTP)


def test_friendly_message_matches_nothing():
    assert rules.find_red_flags(FRIENDLY) == []


def test_matches_have_required_fields():
    for m in rules.find_red_flags(HI_MUM):
        assert {"id", "name", "weight", "evidence"} <= set(m)
        assert m["weight"] > 0


def test_url_heuristics():
    assert rules.analyse_url("http://gtbank-verify.xyz/login")
    assert rules.analyse_url("https://bit.ly/abc123")
    assert rules.analyse_url("https://www.gtbank.com") == []
    assert rules.analyse_url("https://example.com/page") == []
    assert "suspicious_link" in ids("Please check this", "http://opay-secure-login.top")


def test_url_inside_message_text_is_checked():
    assert "suspicious_link" in ids("Verify now at http://palmpay-kyc.xyz today")


# ---- scorer ----------------------------------------------------------------
def test_level_thresholds():
    assert scorer.level_for(75) == "Critical"
    assert scorer.level_for(74) == "High"
    assert scorer.level_for(55) == "High"
    assert scorer.level_for(54) == "Medium"
    assert scorer.level_for(30) == "Medium"
    assert scorer.level_for(29) == "Low"


def test_rules_only_scam_is_critical_or_high():
    result = scorer.analyse(HI_MUM)  # no model injected
    assert result["risk_level"] in ("Critical", "High")
    assert result["ai_probability"] is None
    assert result["engine_mode"] == "rules-only"
    assert result["matched_rules"]
    assert any("old number" in a.lower() or "known" in a.lower() for a in result["advice"])


def test_rules_only_friendly_is_low():
    result = scorer.analyse(FRIENDLY)
    assert result["risk_level"] == "Low"
    assert result["score"] < 30


def test_ai_alone_cannot_reach_high():
    result = scorer.analyse("Some odd message with no known patterns", proba_fn=lambda _t: 1.0)
    assert result["risk_level"] in ("Medium", "Low")
    assert result["score"] <= 54


def test_ai_boosts_when_rules_agree():
    base = scorer.analyse(HI_MUM)["score"]
    boosted = scorer.analyse(HI_MUM, proba_fn=lambda _t: 0.95)["score"]
    assert boosted >= base or base == 100


def test_advice_is_specific_to_rules():
    otp = scorer.analyse("Please forward the OTP you received, I am locked out. Don't tell anyone.")
    assert any("OTP" in a or "PIN" in a for a in otp["advice"])
    job = scorer.analyse("Pay ₦15,000 registration fee to secure your job slot. Hurry, limited vacancies.")
    assert any("employers" in a.lower() for a in job["advice"])


def test_result_has_all_fields():
    result = scorer.analyse(HI_MUM)
    for key in ("risk_level", "score", "matched_rules", "ai_probability", "advice", "summary"):
        assert key in result
    assert 0 <= result["score"] <= 100


# ---- pipeline / model --------------------------------------------------------
def test_pipeline_validates_input():
    for bad in ("", "   ", None):
        try:
            analyse_message(bad)
        except ValueError:
            continue
        raise AssertionError("empty input should raise ValueError")


def test_pipeline_works_with_or_without_model():
    result = analyse_message(HI_MUM)
    assert result["risk_level"] in ("Critical", "High")
    assert analyse_message(FRIENDLY)["risk_level"] == "Low"


def test_model_probability_range_and_direction():
    if not model.is_available():
        return  # run `python train_model.py` first
    scam_p, clean_p = model.predict_proba(HI_MUM), model.predict_proba(FRIENDLY)
    assert 0.0 <= clean_p <= scam_p <= 1.0
    assert scam_p > 0.5 > clean_p


def test_all_training_samples_rules_and_pipeline():
    """Every scam sample should reach at least Medium; clean samples should be Low."""
    path = Path(__file__).resolve().parent.parent / "data" / "scam_samples.csv"
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) >= 30
    for row in rows:
        level = analyse_message(row["text"])["risk_level"]
        if row["label"] == "1":
            assert level in ("Medium", "High", "Critical"), f"missed scam: {row['text']}"
        else:
            assert level == "Low", f"false alarm ({level}): {row['text']}"


if __name__ == "__main__":  # run without pytest
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print(f"FAIL {name}: {exc}")
    raise SystemExit(1 if failed else 0)
