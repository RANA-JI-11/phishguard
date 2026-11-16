from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, auth

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.post("", response_model=schemas.ApiKeyOut)
def create_api_key(
    payload: schemas.ApiKeyCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    key = models.ApiKey(key=auth.generate_api_key(), label=payload.label, user_id=user.id)
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


@router.get("", response_model=List[schemas.ApiKeyOut])
def list_api_keys(
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    return db.query(models.ApiKey).filter(models.ApiKey.user_id == user.id).all()


@router.delete("/{key_id}")
def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    key = db.query(models.ApiKey).filter(
        models.ApiKey.id == key_id, models.ApiKey.user_id == user.id
    ).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.is_active = False
    db.commit()
    return {"detail": "API key revoked"}
