import datetime as dt
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app import models

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str) -> str:
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def generate_api_key() -> str:
    return "pg_" + secrets.token_urlsafe(32)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    api_key: str = Depends(api_key_header),
    db: Session = Depends(get_db),
):
    """
    Two ways to authenticate:
      1. JWT bearer token (used by the web dashboard / frontend login).
      2. X-API-Key header (used by developers integrating programmatically - this is
         the key monetization path: paid tiers get higher rate limits).
    """
    if api_key:
        key_row = db.query(models.ApiKey).filter(
            models.ApiKey.key == api_key, models.ApiKey.is_active == True  # noqa: E712
        ).first()
        if not key_row:
            raise HTTPException(status_code=401, detail="Invalid API key")
        key_row.last_used_at = dt.datetime.utcnow()
        db.commit()
        user = db.query(models.User).filter(models.User.id == key_row.user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="API key has no owner")
        return user

    if token:
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            user_id = payload.get("sub")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated. Provide a Bearer token or X-API-Key header.",
    )


def get_optional_user(
    token: str = Depends(oauth2_scheme),
    api_key: str = Depends(api_key_header),
    db: Session = Depends(get_db),
):
    """Same as get_current_user but returns None instead of raising - used for
    endpoints that work for anonymous visitors too (e.g. a public 'quick scan' demo)."""
    try:
        return get_current_user(token, api_key, db)
    except HTTPException:
        return None
