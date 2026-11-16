"""
Lightweight i18n for fixed UI/API strings (verdict labels, alert messages).
The AI agent's free-text explanations are generated directly in the target
language by Claude (see ai_agent.py) - this file only covers static strings
that need to be instant and not cost an LLM call.
"""

TRANSLATIONS = {
    "en": {
        "safe": "Safe", "suspicious": "Suspicious", "phishing": "Phishing",
        "alert_subject": "PhishGuard Alert: High-risk URL detected",
    },
    "hi": {
        "safe": "सुरक्षित", "suspicious": "संदिग्ध", "phishing": "फ़िशिंग",
        "alert_subject": "PhishGuard चेतावनी: उच्च-जोखिम URL मिला",
    },
    "es": {
        "safe": "Seguro", "suspicious": "Sospechoso", "phishing": "Phishing",
        "alert_subject": "Alerta de PhishGuard: URL de alto riesgo detectada",
    },
    "fr": {
        "safe": "Sûr", "suspicious": "Suspect", "phishing": "Hameçonnage",
        "alert_subject": "Alerte PhishGuard : URL à haut risque détectée",
    },
}


def t(key: str, lang: str = "en") -> str:
    lang_dict = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    return lang_dict.get(key, TRANSLATIONS["en"].get(key, key))
