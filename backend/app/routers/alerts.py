from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, auth

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("")
def create_alert_config(
    payload: schemas.AlertConfigCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    cfg = models.AlertConfig(
        user_id=user.id, channel=payload.channel, target=payload.target,
        min_risk_score=payload.min_risk_score,
    )
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return {"id": cfg.id, "channel": cfg.channel, "min_risk_score": cfg.min_risk_score}


@router.get("")
def list_alert_configs(
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    rows = db.query(models.AlertConfig).filter(models.AlertConfig.user_id == user.id).all()
    return [
        {"id": r.id, "channel": r.channel, "target": r.target,
         "min_risk_score": r.min_risk_score, "is_active": r.is_active}
        for r in rows
    ]
