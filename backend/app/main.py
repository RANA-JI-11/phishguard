from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.routers import auth, scan, api_keys, history, agent, alerts, billing, email_scan, team

app = FastAPI(
    title="PhishGuard AI API",
    description="AI-Based Smart Phishing Website Detection and URL Risk Analyzer.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your real frontend domain before production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    Base.metadata.create_all(bind=engine)
    print("[PhishGuard] Database connected, tables ready.")
except Exception as exc:
    raise SystemExit(
        "\n[PhishGuard] Cannot connect to the database.\n"
        "Check DATABASE_URL in .env (user, password, database name) and that PostgreSQL is running.\n"
        f"Details: {exc}\n"
    )

for r in (auth, scan, email_scan, api_keys, history, agent, alerts, billing, team):
    app.include_router(r.router)


@app.get("/")
def root():
    return {"service": "PhishGuard AI", "status": "running", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}
