import io

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from PIL import Image
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, auth
from app.usage import check_and_increment_usage
from app.routers.scan import _run_single_scan

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/qr")
async def scan_qr_code(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    """Feature: QR-code phishing detection (Temporarily stubbed for local setup)."""
    raise HTTPException(
        status_code=501, 
        detail="QR code scanning endpoint is temporarily disabled during local development setup."
    )