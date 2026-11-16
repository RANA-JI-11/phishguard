import smtplib
from email.mime.text import MIMEText

import requests

from app.config import settings


def send_slack_alert(webhook_url: str, text: str) -> bool:
    try:
        resp = requests.post(webhook_url, json={"text": text}, timeout=5)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def send_generic_webhook(webhook_url: str, payload: dict) -> bool:
    try:
        resp = requests.post(webhook_url, json=payload, timeout=5)
        return resp.ok
    except requests.RequestException:
        return False


def send_email_alert(to_email: str, subject: str, body: str) -> bool:
    if not settings.SMTP_HOST:
        return False
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_USER
        msg["To"] = to_email
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, [to_email], msg.as_string())
        return True
    except Exception:
        return False


def dispatch_alert(channel: str, target: str, url: str, risk_score: float, verdict: str):
    text = (f"High-risk URL detected: {url}\nVerdict: {verdict.upper()} "
            f"(risk score {risk_score}/100)")
    if channel == "slack":
        return send_slack_alert(target, text)
    if channel == "webhook":
        return send_generic_webhook(target, {"url": url, "risk_score": risk_score, "verdict": verdict})
    if channel == "email":
        return send_email_alert(target, "PhishGuard Alert: High-risk URL detected", text)
    return False
