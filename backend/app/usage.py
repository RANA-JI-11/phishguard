import datetime as dt

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app import models
from app.config import PLAN_LIMITS


def check_and_increment_usage(db: Session, user: models.User, amount: int = 1):
    """Enforces the daily scan limit for the user's plan and logs usage.
    This is the core of the monetization gate: Free users hit a wall and
    are prompted to upgrade to Pro/Business for higher limits."""
    today = dt.date.today().isoformat()
    plan = user.plan if user.plan in PLAN_LIMITS else "free"
    limit = PLAN_LIMITS[plan]["daily_scans"]

    row = db.query(models.UsageLog).filter(
        models.UsageLog.user_id == user.id, models.UsageLog.date == today
    ).first()

    current = row.scan_count if row else 0
    if current + amount > limit:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Daily scan limit reached for the '{plan}' plan ({limit}/day). "
                f"Upgrade your plan to continue: POST /billing/checkout"
            ),
        )

    if row:
        row.scan_count += amount
    else:
        row = models.UsageLog(user_id=user.id, date=today, scan_count=amount)
        db.add(row)
    db.commit()
