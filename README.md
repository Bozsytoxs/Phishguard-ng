# PhishGuard NG

**Detect. Understand. Stay Safe.**
Team **CyberShield NG** · Nascomsoft Hackathon 2.0 · Software: responsive web application

PhishGuard NG lets Nigerian students, small businesses and community members paste a suspicious
WhatsApp / SMS / email message (and an optional link) and instantly get:

- a **risk level** (Low / Medium / High / Critical) and score out of 100
- the **Nigerian red flags** that were matched, with the exact words that triggered them
- **numbered safety advice** specific to those red flags

No login. Mobile-first. The core analysis runs fully offline on the server: no OpenAI or paid API.

## How it works

1. **Rule engine** (`engine/rules.py`): regex heuristics for new-number scams, urgent money requests, OTP requests,
   job fees, secrecy pressure, BVN/NIN/CBN impersonation, fake invoices, prizes, investment schemes and lookalike links.
   This drives the explanations.
2. **Local ML model** (`engine/model.py`): TF-IDF + Logistic Regression (scikit-learn, saved with joblib). A second
   signal that helps with wording the rules do not know. If model files are missing, the app falls back to rules-only mode.
3. **Hybrid scorer** (`engine/scorer.py`): rules set the score; the model boosts it when it agrees and can lift a
   weak-rule message to Medium, but never to High on its own.
   Levels: Critical ≥ 75, High ≥ 55, Medium ≥ 30, otherwise Low.

```
phishguard-ng/
├── app.py               FastAPI app (API + serves the UI)
├── train_model.py       trains the model from data/scam_samples.csv
├── engine/              rules.py · model.py · scorer.py · pipeline.py · reputation.py (optional)
├── data/scam_samples.csv   64 synthetic Nigerian scam + clean messages (text,label)
├── models/              joblib files appear here after training
├── static/              index.html · style.css · app.js
└── tests/test_engine.py
```

## Install

Python 3.10+ is recommended.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Train the model

```bash
python train_model.py
```

This prints a cross-validated accuracy and writes `models/vectorizer.joblib` and `models/classifier.joblib`.
The dataset is small and synthetic, so treat the accuracy as a demo figure. Add more rows to
`data/scam_samples.csv` (`text,label` with 1 = scam, 0 = clean) and re-run to improve it.

## Run locally

```bash
uvicorn app:app --reload
```

Open http://127.0.0.1:8000. To try it on a phone on the same Wi-Fi: `uvicorn app:app --host 0.0.0.0 --port 8000`,
then open `http://<your-computer-ip>:8000`.

API: `POST /api/analyse` with `{"text": "...", "url": "..."}` returns `risk_level`, `score`, `matched_rules`,
`ai_probability`, `advice`, `summary`. Health check: `GET /api/health`.

## Run the tests

```bash
python -m pytest -q
# or, without pytest:
python -m tests.test_engine
```

## Demo script (2 minutes)

1. Open the app on a phone and tap **Check a message**.
2. Tap **Family emergency**, then **Analyse message**. Expect **Critical**, with the red flags
   “new number story”, “urgent request to send money”, “keep it secret” and numbered advice such as calling the old known number.
3. Tap **Check another message**, then paste a friendly message such as
   `Hey, are we still meeting at 4pm for the group project?`. Expect **Low**.
4. Try **Job fee**, **OTP request**, or paste `http://gtbank-verify.xyz/login` in the link box to show the link checks.
5. Open **Awareness** and **About**. Point out that every score shows *why*, and that we never claim 100% accuracy.

## Optional: external URL reputation

Set `GOOGLE_SAFE_BROWSING_API_KEY` to add Google Safe Browsing as an extra signal for the link field.
Without a key (or without internet) nothing changes; the core analysis never depends on it.

## Deploy (free tier)

**Render / Railway**
- Build command: `pip install -r requirements.txt && python train_model.py`
- Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`

## Limitations (be honest in the pitch)

- The rules and dataset are hand-written and small; new scam wording can slip through, and some genuine messages
  can be flagged. The tool gives guidance, not certainty.
- English and Nigerian Pidgin phrases are covered lightly; no full localisation yet.
- Lookalike-link checks use a short list of brands and risky endings.

## Team

| Name | Role |
|---|---|
| J. S. Tapkum | Cybersecurity |
| Markus Godwin | AI / Machine Learning |
| Habila Injine | Cybersecurity |
| Hussaini Muhammad Nasir | Data Science & ML |
| Umar Faruq | Cybersecurity |
