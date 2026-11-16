"""
Extracts numeric/boolean features from a raw URL string.
These features feed both the ML model (train_model.py / predictor.py)
and the human-readable "risk factors" shown to the end user.

No network calls happen here - this is pure lexical analysis, so it's
instant and free to run on every request. Network-dependent signals
(domain age, SSL validity, blacklists) live in app/integrations/ and are
merged in predictor.py.
"""
import re
import math
from urllib.parse import urlparse
import tldextract

_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # uses bundled snapshot, no network

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "confirm", "password", "webscr", "ebayisapi", "paypal", "billing",
    "suspend", "alert", "recover", "unlock", "wallet", "gift", "bonus",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st",
]

FEATURE_NAMES = [
    "url_length", "hostname_length", "num_dots", "num_hyphens", "num_digits",
    "num_special_chars", "num_subdomains", "has_ip", "has_at_symbol",
    "has_https", "has_port", "is_shortened", "suspicious_keyword_count",
    "digit_letter_ratio", "entropy", "has_double_slash_redirect",
]

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _safe_port(parsed):
    try:
        return parsed.port
    except ValueError:
        return None


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_features(url: str) -> dict:
    url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url  # normalize so urlparse works

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").strip(".")
    ext = _TLD(url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": len(re.findall(r"[^a-zA-Z0-9./:_-]", url)),
        "num_subdomains": max(len(ext.subdomain.split(".")) if ext.subdomain else 0, 0),
        "has_ip": 1 if IP_PATTERN.match(hostname) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_port": 1 if _safe_port(parsed) else 0,
        "is_shortened": 1 if registered_domain in URL_SHORTENERS else 0,
        "suspicious_keyword_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()),
        "digit_letter_ratio": (
            sum(c.isdigit() for c in url) / max(sum(c.isalpha() for c in url), 1)
        ),
        "entropy": round(_shannon_entropy(hostname), 3),
        "has_double_slash_redirect": 1 if url.rfind("//") > 7 else 0,
    }

    meta = {
        "hostname": hostname,
        "registered_domain": registered_domain,
        "scheme": parsed.scheme.lower(),
        "path": parsed.path,
        "path_query": (parsed.path or "") + ("?" + parsed.query if parsed.query else ""),
        "domain_label": ext.domain,
        "subdomain": ext.subdomain,
        "suffix": ext.suffix,
    }
    return {"features": features, "meta": meta}


def features_to_vector(features: dict) -> list:
    """Ordered vector for the ML model, matching FEATURE_NAMES order."""
    return [features[name] for name in FEATURE_NAMES]


def human_readable_risk_factors(features: dict, meta: dict, extra: dict = None) -> list:
    """Turns raw features (+ optional external signals in `extra`) into
    plain-English reasons a non-technical user can understand."""
    reasons = []
    if features["has_ip"]:
        reasons.append("The link uses a raw IP address instead of a domain name.")
    if not features["has_https"]:
        reasons.append("The site does not use a secure HTTPS connection.")
    if features["has_at_symbol"]:
        reasons.append("The URL contains an '@' symbol, a common cloaking trick.")
    if features["suspicious_keyword_count"] > 0:
        reasons.append(f"The URL contains {features['suspicious_keyword_count']} suspicious keyword(s) "
                        f"often used in phishing (e.g. 'login', 'verify', 'secure').")
    if features["num_subdomains"] >= 3:
        reasons.append("The URL has an unusually high number of subdomains.")
    if features["url_length"] > 75:
        reasons.append("The URL is unusually long, which can be used to hide the real destination.")
    if features["is_shortened"]:
        reasons.append("This is a shortened URL, which can hide the true destination website.")
    if features["entropy"] > 4.0:
        reasons.append("The domain name looks randomly generated (high character entropy).")
    if features["num_hyphens"] >= 4:
        reasons.append("The domain contains many hyphens, common in fake lookalike domains.")

    if extra:
        if extra.get("domain_age_days") is not None and extra["domain_age_days"] < 90:
            reasons.append(f"The domain was registered only {extra['domain_age_days']} days ago.")
        if extra.get("ssl_valid") is False:
            reasons.append("The site's SSL certificate is invalid or expired.")
        if extra.get("blacklisted"):
            reasons.append("This domain appears on a known phishing/malware blacklist.")

    if not reasons:
        reasons.append("No major suspicious patterns were found in the URL structure.")
    return reasons
