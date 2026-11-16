# PhishGuard AI

AI-powered phishing URL detection.

- `frontend/` — Next.js dashboard (deploy on Vercel, Root Directory = `frontend`)
- `backend/` — FastAPI + ML detector (deploy on Render/Railway)

## Run locally
```bash
# backend
cd backend && python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # fill your keys
uvicorn app.main:app --reload

# frontend
cd frontend && pnpm install && pnpm dev
```
