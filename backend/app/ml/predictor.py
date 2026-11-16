"""
Final URL risk scoring = rule engine (app/ml/rules.py) + optional trained ML model.

* Without phishing_model.joblib the rule engine alone decides (already strong
  on brand impersonation / typosquatting / look-alike domains).
* With a trained model, the two are combined; an official-domain match
  (trusted) always wins over the ML score to avoid false positives.
"""
import os
import re
import joblib

from app.ml.feature_extractor import extract_features, features_to_vector
from app.ml import rules

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")
PHISHING_THRESHOLD = 60.0
SUSPICIOUS_THRESHOLD = 35.0

_model_bundle = None
if os.path.exists(MODEL_PATH):
    try:
        _model_bundle = joblib.load(MODEL_PATH)
    except Exception as exc:  # corrupted / version-mismatched model must not crash the API
        print(f"[PhishGuard] Could not load ML model ({exc}); using rule engine only.")


def verdict_from_score(score: float) -> str:
    if score >= PHISHING_THRESHOLD:
        return "phishing"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "safe"


def clean_url(url: str) -> str:
    url = (url or "").strip().strip("<>\"'")
    url = re.sub(r"\s+", "", url)
    if not url:
        raise ValueError("URL is empty")
    if len(url) > 2048:
        raise ValueError("URL is too long (max 2048 characters)")
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", url)
    if m and m.group(1).lower() not in ("http", "https") and "://" not in url[:12]:
        raise ValueError(f"Unsupported URL scheme '{m.group(1)}'. Only http/https links can be scanned.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    return url


def predict_url(url: str) -> dict:
    url = clean_url(url)
    extraction = extract_features(url)
    features, meta = extraction["features"], extraction["meta"]

    rule = rules.analyze(
        url=url, hostname=meta["hostname"], registered_domain=meta["registered_domain"],
        domain_label=meta["domain_label"], subdomain=meta["subdomain"], suffix=meta["suffix"],
        scheme=meta["scheme"], path_query=meta["path_query"], features=features,
    )
    rule_score = rule["score"]

    if _model_bundle is not None:
        try:
            proba = _model_bundle["model"].predict_proba([features_to_vector(features)])[0]
            ml_score = float(proba[1]) * 100
            confidence = round(max(proba) * 100, 2)
            if rule["trusted"]:
                risk = min(rule_score, 20.0) if rule_score else min(ml_score, 10.0)
            else:
                risk = max(rule_score, 0.5 * ml_score + 0.5 * rule_score)
            method = "rules+ml_model"
        except Exception:
            risk, confidence, method = rule_score, 75.0, "rules_only"
    else:
        risk = rule_score
        confidence = 90.0 if (rule["trusted"] or rule_score >= 60) else 70.0
        method = "rules_only"

    risk = round(min(max(risk, 0.0), 100.0), 2)
    return {
        "url": url,
        "verdict": verdict_from_score(risk),
        "risk_score": risk,
        "ml_confidence": confidence,
        "method": method,
        "features": features,
        "meta": meta,
        "rule_reasons": rule["reasons"],
        "trusted": rule["trusted"],
    }
