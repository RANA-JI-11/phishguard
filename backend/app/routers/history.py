from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, auth

router = APIRouter(prefix="/history", tags=["history"])


@router.get("")
def get_history(
    limit: int = 50,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    rows = (
        db.query(models.ScanHistory)
        .filter(models.ScanHistory.user_id == user.id)
        .order_by(models.ScanHistory.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "url": r.url, "verdict": r.verdict, "risk_score": r.risk_score,
            "ai_explanation": r.ai_explanation, "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    """Powers the frontend dashboard: totals by verdict + trend over time."""
    base_q = db.query(models.ScanHistory).filter(models.ScanHistory.user_id == user.id)
    total = base_q.count()

    by_verdict = dict(
        db.query(models.ScanHistory.verdict, func.count(models.ScanHistory.id))
        .filter(models.ScanHistory.user_id == user.id)
        .group_by(models.ScanHistory.verdict)
        .all()
    )

    daily = (
        db.query(
            func.date(models.ScanHistory.created_at).label("day"),
            func.count(models.ScanHistory.id),
        )
        .filter(models.ScanHistory.user_id == user.id)
        .group_by("day")
        .order_by("day")
        .all()
    )

    return {
        "total_scans": total,
        "by_verdict": by_verdict,
        "daily_trend": [{"date": str(day), "count": count} for day, count in daily],
        "plan": user.plan,
    }
