import datetime as dt

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, auth
from app.usage import check_and_increment_usage
from app.config import PLAN_LIMITS
from app.ml.predictor import predict_url, verdict_from_score
from app.ai_agent import explain_scan
from app.integrations import threat_intel, alerts

router = APIRouter(prefix="/scan", tags=["scan"])


def _run_single_scan(db: Session, user: models.User, url: str, language: str, source: str) -> dict:
    try:
        prediction = predict_url(url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    url = prediction["url"]
    meta = prediction["meta"]

    risk_score = prediction["risk_score"]
    reasons = list(prediction["rule_reasons"])
    extra = {}

    # Network checks only for non-official domains (official domains over HTTPS are trusted).
    if not prediction["trusted"]:
        extra = threat_intel.enrich(url, meta["hostname"], meta["registered_domain"])
        if extra.get("blacklisted"):
            risk_score = max(risk_score, 97.0)
            reasons.insert(0, "Listed as phishing/malware by: " + ", ".join(extra["blacklist_sources"]) + ".")
        age = extra.get("domain_age_days")
        if age is not None:
            if age < 30:
                risk_score = min(risk_score + 25, 100.0)
                reasons.append(f"The domain was registered only {age} days ago (brand-new domains are very common in phishing).")
            elif age < 90:
                risk_score = min(risk_score + 12, 100.0)
                reasons.append(f"The domain is only {age} days old.")
        if extra.get("ssl_valid") is False:
            risk_score = min(risk_score + 15, 100.0)
            reasons.append("The site's SSL certificate is invalid or expired.")

    risk_score = round(risk_score, 2)
    verdict = verdict_from_score(risk_score)

    if verdict == "safe" and not prediction["trusted"]:
        checked = extra.get("checks_run") or []
        reasons.append(
            "No phishing patterns found" + (f" and not listed in: {', '.join(checked)}." if checked else ".")
            + " No tool is 100% perfect, so still verify the address before entering passwords."
        )
    if not reasons:
        reasons.append("No suspicious patterns found.")

    explanation = explain_scan(url, verdict, risk_score, reasons, language)

    record = models.ScanHistory(
        user_id=user.id if user else None, url=url, verdict=verdict, risk_score=risk_score,
        ml_confidence=prediction["ml_confidence"], risk_factors=reasons,
        ai_explanation=explanation, source=source,
    )
    db.add(record)
    db.commit()

    if user:
        try:
            alert_configs = db.query(models.AlertConfig).filter(
                models.AlertConfig.user_id == user.id, models.AlertConfig.is_active == True  # noqa: E712
            ).all()
            for cfg in alert_configs:
                if risk_score >= cfg.min_risk_score:
                    alerts.dispatch_alert(cfg.channel, cfg.target, url, risk_score, verdict)
        except Exception:
            pass  # an alert failure must never fail the scan itself

    return {
        "url": url, "verdict": verdict, "risk_score": risk_score,
        "ml_confidence": prediction["ml_confidence"], "risk_factors": reasons,
        "ai_explanation": explanation, "checked_at": dt.datetime.utcnow().isoformat(),
    }


@router.post("", response_model=schemas.ScanResult)
def scan_url(
    payload: schemas.ScanRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    check_and_increment_usage(db, user, amount=1)
    language = payload.language or user.preferred_language
    return _run_single_scan(db, user, payload.url, language, source="api")


@router.post("/bulk", response_model=schemas.BulkScanResponse)
def scan_bulk(
    payload: schemas.BulkScanRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    plan = user.plan if user.plan in PLAN_LIMITS else "free"
    if not PLAN_LIMITS[plan]["bulk_scan"]:
        raise HTTPException(
            status_code=403,
            detail="Bulk scanning requires the Pro or Business plan. POST /billing/checkout to upgrade.",
        )
    if not payload.urls or len(payload.urls) > 100:
        raise HTTPException(status_code=422, detail="Send between 1 and 100 URLs.")
    check_and_increment_usage(db, user, amount=len(payload.urls))
    language = payload.language or user.preferred_language
    results = [_run_single_scan(db, user, url, language, source="api_bulk") for url in payload.urls]
    return {"results": results}


@router.post("/public-demo", response_model=schemas.ScanResult)
def scan_public_demo(payload: schemas.ScanRequest, db: Session = Depends(get_db)):
    """
    Unauthenticated, tightly-limited endpoint for a marketing/landing-page
    'try it now' box. Does NOT save to a user's history (no user_id) and
    should be rate-limited at the reverse-proxy/CDN level in production.
    """
    return _run_single_scan(db, None, payload.url, "en", source="public_demo")
