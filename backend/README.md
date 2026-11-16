# PhishGuard AI — Smart Phishing Website Detection & URL Risk Analyzer

A production-shaped backend for your B.Tech minor project, turned into something
you can actually launch and charge money for. Built in Python (FastAPI) with
PostgreSQL, a real machine-learning phishing classifier, and a Claude-powered
AI agent that explains every verdict in plain language — in multiple languages.

This is **backend + AI + database only**, by design — you said you'll build the
frontend separately, so every endpoint is documented in `docs/API_DOCUMENTATION.md`
for whoever builds that UI (or for you, if you use Claude/ChatGPT/a no-code tool
to build it against this API).

---

## 1. Why PostgreSQL (not MongoDB)

You asked which to pick. **PostgreSQL** — here's why, specifically for this project:

- You have **users, subscriptions, payments, API keys, teams** — all related to each
  other. That's relational data, and it needs to stay perfectly consistent (you
  never want a user charged but not upgraded, or upgraded but not charged).
  Postgres gives you real transactions; MongoDB makes you build that consistency
  yourself.
- Every serious paid API product (Stripe integration, usage metering, dashboards)
  is easiest to build correctly on a relational database.
- Your dashboard/analytics queries (scans per day, verdict breakdown, team reports)
  are simple SQL `GROUP BY` queries — this is exactly what Postgres is best at.
- MongoDB would only have been the better call if your core data were deeply
  nested/unstructured (e.g. storing entire raw scraped web pages). You can still
  add MongoDB later *just* for that (see Future Scope), but don't start there.

## 2. Architecture

```
Browser Extension / Mobile App / Web Dashboard  (you'll build this)
                    │  HTTPS (JSON)
                    ▼
        FastAPI backend  (this repo)
        ├── Auth (JWT + API keys)
        ├── URL feature extraction (lexical analysis)
        ├── ML model (RandomForest) ── trained offline, loaded at runtime
        ├── Threat intel enrichment (Google Safe Browsing, VirusTotal, WHOIS, SSL)
        ├── AI Agent (Claude) — explains verdicts + answers follow-up questions
        ├── Alerts (Slack / email / webhook)
        └── Billing (Stripe) — this is how you earn money
                    │
                    ▼
              PostgreSQL  (users, scans, api keys, subscriptions, teams)
```

## 3. Local setup

```bash
# 1. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install PostgreSQL locally (or use a free hosted one — see below)
#    Then create the database:
createdb phishguard

# 4. Copy the environment template and fill in real values
cp .env.example .env
#    At minimum set DATABASE_URL and ANTHROPIC_API_KEY to get the AI
#    explanations working. Everything else has safe fallbacks.

# 5. Run the API
uvicorn app.main:app --reload

# 6. Open the interactive API docs (auto-generated, share this URL with
#    whoever builds your frontend)
open http://localhost:8000/docs
```

**Free hosted PostgreSQL options** (no credit card needed to start):
[Neon](https://neon.tech), [Supabase](https://supabase.com), [Railway](https://railway.app).
Just paste the connection string they give you into `DATABASE_URL`.

## 4. Training the real ML model

Right now, if no trained model file exists, the API automatically uses a
transparent **heuristic scorer** (see `app/ml/predictor.py`) so it works out
of the box. To get real ML accuracy for your report/demo:

```bash
# Download a labeled dataset, e.g.:
#   https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls
# It needs two columns: url, label   (label: 1 = phishing, 0 = legitimate)

python -m app.ml.train_model --data phishing_dataset.csv
```

This prints accuracy/precision/recall/ROC-AUC (good numbers for your project
report) and saves `app/ml/phishing_model.joblib`, which the API picks up
automatically on next restart.

## 5. The AI Agent

Every scan gets a plain-language explanation from Claude (`app/ai_agent.py`),
in the user's chosen language. There's also a conversational endpoint
(`POST /agent/chat`) so users can ask follow-up questions like *"is it safe to
enter my password on this page?"*. Set `ANTHROPIC_API_KEY` in `.env` to enable it
— without a key it still works using a simpler template explanation.

## 6. Multi-language support

- `preferred_language` is stored per user (`en`, `hi`, `es`, `fr`, ...).
- The AI agent writes its explanations directly in that language.
- Fixed strings (verdict labels, alert messages) come from
  `app/i18n/translations.py` — add more languages there any time.

## 7. What's included vs. what you still need to do

**Included and working:**
- Signup/login (JWT), API key issuance & revocation
- URL feature extraction + ML prediction + heuristic fallback
- Threat intel enrichment hooks (Google Safe Browsing, VirusTotal, WHOIS, SSL)
- AI agent explanations + chat
- Scan history + dashboard stats
- QR code scanning, email link scanning
- Alerts (Slack/email/webhook)
- Team accounts
- Stripe billing (checkout + webhook) — the actual "earn money" mechanism

**You still need to:**
- Deploy it (Railway/Render/Fly.io/your own VPS all work well with FastAPI)
- Create a real Stripe account and products, put the price IDs in `.env`
- Train the model on a real dataset for your report (`app/ml/train_model.py`)
- Build the frontend against `docs/API_DOCUMENTATION.md`
- Set `allow_origins` in `app/main.py` to your real frontend domain before launch

See `docs/MONETIZATION_GUIDE.md` for how to actually turn this into income,
and `docs/API_DOCUMENTATION.md` for the full endpoint reference for your
frontend developer.
