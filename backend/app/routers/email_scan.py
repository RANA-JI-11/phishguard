import re

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, auth
from app.usage import check_and_increment_usage
from app.routers.scan import _run_single_scan

router = APIRouter(prefix="/scan", tags=["scan"])

URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


class EmailScanRequest(BaseModel):
    email_text: str


@router.post("/email")
def scan_email(
    payload: EmailScanRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    """Feature: paste raw email content (body/headers) and every embedded
    link is extracted and scanned. Great building block for a Gmail/Outlook
    add-on later."""
    urls = list(dict.fromkeys(URL_REGEX.findall(payload.email_text)))  # de-dupe, keep order
    if not urls:
        return {"urls_found": 0, "results": []}

    check_and_increment_usage(db, user, amount=len(urls))
    results = [_run_single_scan(db, user, u, user.preferred_language, source="email") for u in urls]
    highest_risk = max(r["risk_score"] for r in results)
    return {
        "urls_found": len(urls),
        "overall_verdict": "phishing" if highest_risk >= 70 else "suspicious" if highest_risk >= 35 else "safe",
        "results": results,
    }
