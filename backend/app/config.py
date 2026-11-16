"""
Central configuration for the whole backend.
All values are loaded from environment variables (.env file in development,
real environment variables in production / Docker / hosting provider).
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://phishguard_user:changeme@localhost:5432/phishguard"

    # Auth
    JWT_SECRET_KEY: str = "insecure-dev-secret-change-me"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # AI Agent
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"

    # Threat intel
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # Billing
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRICE_ID_PRO: str = ""
    STRIPE_PRICE_ID_BUSINESS: str = ""

    # Alerts
    SLACK_WEBHOOK_URL: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""

    DEFAULT_LANGUAGE: str = "en"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# ---- Plan definitions used across billing + rate limiting ----
PLAN_LIMITS = {
    "free": {"daily_scans": 50, "bulk_scan": False, "price_inr": 0},
    "pro": {"daily_scans": 2000, "bulk_scan": True, "price_inr": 799},
    "business": {"daily_scans": 50000, "bulk_scan": True, "price_inr": 4999},
}
