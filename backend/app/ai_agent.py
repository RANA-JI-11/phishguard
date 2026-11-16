"""
AI explanation layer (Claude). Fully optional and failure-safe: if the API key is
missing/invalid, the network is down or the SDK misbehaves, the app falls back
to a plain template explanation instead of crashing.
"""
from app.config import settings

try:
    from anthropic import Anthropic
    _client = Anthropic(api_key=settings.ANTHROPIC_API_KEY) if settings.ANTHROPIC_API_KEY else None
except Exception as exc:  # SDK / httpx incompatibility must never stop the server from starting
    print(f"[PhishGuard] Anthropic client disabled: {exc}")
    _client = None

LANGUAGE_NAMES = {"en": "English", "hi": "Hindi", "es": "Spanish", "fr": "French", "de": "German", "ar": "Arabic"}


def _template_explanation(verdict: str, risk_score: float, risk_factors: list, lang: str = "en") -> str:
    advice = {
        "phishing": "Do NOT open this link or enter any password, OTP or card details.",
        "suspicious": "Be careful. Do not enter personal information unless you verify the website through its official app or address.",
        "safe": "No known phishing signs were found, but always check the address before entering passwords.",
    }[verdict]
    return f"Verdict: {verdict.upper()} (risk {risk_score}/100). {advice} Reasons: " + " ".join(risk_factors[:4])


def explain_scan(url: str, verdict: str, risk_score: float, risk_factors: list, language: str = "en") -> str:
    fallback = _template_explanation(verdict, risk_score, risk_factors, language)
    if _client is None:
        return fallback
    try:
        lang_name = LANGUAGE_NAMES.get(language, "English")
        prompt = (
            "You are a friendly cybersecurity assistant inside a phishing-detection app.\n"
            f"URL: {url}\nVerdict (already decided, do not change it): {verdict}\n"
            f"Risk score: {risk_score}/100\nDetected reasons: {risk_factors}\n\n"
            f"Write a short (3-4 sentence) plain-language explanation in {lang_name} for a non-technical user. "
            "Say clearly whether the link looks safe, explain the main reasons simply, and give one safety tip. "
            "Never claim a link is 100% safe."
        )
        response = _client.messages.create(
            model=settings.ANTHROPIC_MODEL, max_tokens=300,
            messages=[{"role": "user", "content": prompt}], timeout=15,
        )
        text = "".join(b.text for b in response.content if b.type == "text").strip()
        return text or fallback
    except Exception:
        return fallback


_URL_RE = None


def _find_url(text: str):
    import re
    m = re.search(r"https?://[^\s<>\"']+", text) or re.search(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/[^\s]*)?", text, re.I)
    return m.group(0).rstrip(".,;)") if m else None


def _offline_answer(message: str, url: str | None) -> str:
    """Works without any API key: checks a link with the built-in detector or gives safety tips."""
    target = url or _find_url(message)
    if target:
        try:
            from app.ml.predictor import predict_url
            r = predict_url(target)
            reasons = " ".join(r["rule_reasons"][:3]) or "No suspicious patterns were found."
            advice = {
                "phishing": "Do not open it and never enter passwords, OTP or card details.",
                "suspicious": "Be careful. Open the company's official app or type its official address yourself.",
                "safe": "It looks fine, but always double-check the address before entering a password.",
            }[r["verdict"]]
            return f"I checked {r['url']}: {r['verdict'].upper()} (risk {r['risk_score']}/100). {reasons} {advice}"
        except Exception:
            pass
    low = message.lower()
    if any(w in low for w in ("otp", "kyc", "bank", "upi", "refund", "lottery", "prize")):
        return ("Banks, UPI apps and government offices never ask for your OTP, PIN or password by call, SMS or link. "
                "If a message creates urgency (account blocked, KYC expiring, prize won), treat it as a scam: do not click, "
                "and contact the company only through its official app or website.")
    return ("Quick phishing checklist: 1) Check the real domain (the part just before .com/.in). 2) Be careful with urgent "
            "messages and shortened links. 3) Never enter passwords after clicking an email link, open the official site yourself. "
            "Paste a link here and I will check it for you.")


def agent_chat(message: str, url: str | None, history: list, language: str = "en") -> str:
    if _client is None:
        return _offline_answer(message, url)
    try:
        lang_name = LANGUAGE_NAMES.get(language, "English")
        system_prompt = (
            f"You are PhishGuard's AI safety assistant. Answer in {lang_name}. Be concise and practical. "
            + (f"The user is asking about this URL: {url}. " if url else "")
            + "You have no live browsing access; ground answers in general phishing red flags. "
            "Never say a link is 100% safe; talk in terms of risk level and give actionable advice."
        )
        response = _client.messages.create(
            model=settings.ANTHROPIC_MODEL, max_tokens=400, system=system_prompt,
            messages=history + [{"role": "user", "content": message}], timeout=20,
        )
        return "".join(b.text for b in response.content if b.type == "text").strip() or _offline_answer(message, url)
    except Exception:
        return _offline_answer(message, url)
