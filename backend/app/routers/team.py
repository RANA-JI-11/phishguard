from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, auth

router = APIRouter(prefix="/team", tags=["team"])


class TeamCreate(BaseModel):
    name: str


class TeamInvite(BaseModel):
    email: EmailStr


@router.post("")
def create_team(
    payload: TeamCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    if user.plan != "business":
        raise HTTPException(status_code=403, detail="Teams require the Business plan.")
    team = models.Team(name=payload.name, owner_email=user.email)
    db.add(team)
    db.commit()
    db.refresh(team)
    user.team_id = team.id
    db.commit()
    return {"id": team.id, "name": team.name}


@router.post("/invite")
def invite_member(
    payload: TeamInvite,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    if not user.team_id:
        raise HTTPException(status_code=400, detail="You don't belong to a team yet.")
    member = db.query(models.User).filter(models.User.email == payload.email).first()
    if not member:
        raise HTTPException(status_code=404, detail="No account found for that email. Ask them to sign up first.")
    member.team_id = user.team_id
    db.commit()
    return {"detail": f"{payload.email} added to the team."}


@router.get("/history")
def team_shared_history(
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    """Shared scan history visible to every member of the same team -
    useful for security teams reviewing what colleagues have flagged."""
    if not user.team_id:
        raise HTTPException(status_code=400, detail="You don't belong to a team yet.")
    member_ids = [u.id for u in db.query(models.User).filter(models.User.team_id == user.team_id).all()]
    rows = (
        db.query(models.ScanHistory)
        .filter(models.ScanHistory.user_id.in_(member_ids))
        .order_by(models.ScanHistory.created_at.desc())
        .limit(200)
        .all()
    )
    return [{"url": r.url, "verdict": r.verdict, "risk_score": r.risk_score,
             "created_at": r.created_at.isoformat()} for r in rows]
