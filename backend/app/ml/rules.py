"""
Rule-based phishing detection layer.

Why this exists: a lexical ML model alone cannot know that `paypa1-secure.xyz`
is imitating PayPal. These rules encode that knowledge explicitly:

  * official-domain allowlist per brand (a URL on the REAL domain is trusted)
  * brand impersonation  (brand name inside a domain that is not the brand's)
  * typosquatting / homoglyphs (paypa1, netfIix, rn -> m, 0 -> o ...)
  * brand placed in a subdomain (paypal.com.evil.ru)
  * punycode / non-ASCII lookalike domains
  * risky TLDs, IP hosts, '@' cloaking, shorteners, hyphen stuffing

Every rule returns a score contribution AND a plain-English reason.
"""
import re
import unicodedata
from typing import List, Tuple

# brand keyword -> official registered domains (add your own brands freely)
BRANDS = {
    "google": ["google.com", "google.co.in", "gstatic.com", "youtube.com", "gmail.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "windows.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "github": ["github.com", "githubusercontent.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "flipkart": ["flipkart.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "irctc": ["irctc.co.in"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbilife.co.in"],
    "hdfcbank": ["hdfcbank.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfclife.com"],
    "icicibank": ["icicibank.com"],
    "icici": ["icicibank.com", "icicilombard.com", "iciciprulife.com"],
    "axisbank": ["axisbank.com"],
    "kotak": ["kotak.com", "kotakbank.com"],
    "pnbindia": ["pnbindia.in"],
    "bankofbaroda": ["bankofbaroda.in", "bankofbaroda.com"],
    "canarabank": ["canarabank.com"],
    "npci": ["npci.org.in"],
    "incometax": ["incometax.gov.in", "incometaxindia.gov.in"],
    "uidai": ["uidai.gov.in"],
    "epfindia": ["epfindia.gov.in"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
}

# Very large, well-known sites that need no brand logic but should not be flagged.
POPULAR_SAFE = {
    "wikipedia.org", "reddit.com", "stackoverflow.com", "yahoo.com", "bing.com",
    "zoom.us", "slack.com", "medium.com", "quora.com", "cloudflare.com", "mozilla.org",
    "python.org", "openai.com", "anthropic.com", "claude.ai", "spotify.com", "ebay.com",
    "walmart.com", "bbc.com", "nytimes.com", "indiatimes.com", "hotstar.com", "swiggy.com",
    "zomato.com", "myntra.com", "naukri.com", "gov.in", "nic.in", "ac.in", "edu",
}

RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "support", "zip", "mov",
    "icu", "cam", "buzz", "rest", "fit", "monster", "country", "work", "loan", "men",
    "date", "download", "review", "party", "stream", "gdn", "bid", "cyou", "sbs", "vip",
}

PHISH_WORDS = {
    "login": 6, "signin": 6, "log-in": 6, "verify": 7, "verification": 7, "secure": 5,
    "update": 5, "account": 4, "confirm": 5, "password": 6, "banking": 6, "billing": 5,
    "suspend": 8, "suspended": 8, "unlock": 7, "recover": 5, "wallet": 5, "kyc": 9,
    "otp": 6, "refund": 7, "reward": 6, "prize": 7, "lottery": 9, "bonus": 5, "gift": 4,
    "expire": 5, "urgent": 6, "limited": 3, "validate": 6, "authenticate": 6, "claim": 5,
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc", "rb.gy", "s.id", "shorturl.at",
}

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HEX_IP_RE = re.compile(r"^0x[0-9a-f]+$|^\d{8,10}$")


def _skeleton(s: str) -> str:
    """Collapse look-alike characters so 'paypa1', 'paypaI', 'rnicrosoft' compare equal to the brand."""
    s = unicodedata.normalize("NFKD", s.lower())
    s = s.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    table = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "$": "s", "4": "a", "7": "t", "9": "g"})
    return s.translate(table)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_official(registered_domain: str) -> Tuple[bool, str]:
    """True if the registered domain is an official domain of a known brand."""
    rd = registered_domain.lower()
    for brand, domains in BRANDS.items():
        if rd in domains:
            return True, brand
    return False, ""


def is_popular_safe(registered_domain: str, hostname: str) -> bool:
    rd, host = registered_domain.lower(), hostname.lower()
    if rd in POPULAR_SAFE:
        return True
    # government / academic suffixes: *.gov.in, *.nic.in, *.ac.in, *.edu
    return host.endswith((".gov.in", ".nic.in", ".ac.in", ".gov", ".edu"))


def analyze(url: str, hostname: str, registered_domain: str, domain_label: str,
            subdomain: str, suffix: str, scheme: str, path_query: str, features: dict) -> dict:
    """Returns {"score": 0-100, "reasons": [...], "trusted": bool}."""
    reasons: List[str] = []
    score = 0.0
    host = hostname.lower()
    rd = registered_domain.lower()
    full_lower = url.lower()

    official, brand_of_domain = is_official(rd)
    popular = is_popular_safe(rd, host)
    trusted = (official or popular) and scheme == "https" and not features["has_at_symbol"] and not features["has_ip"]

    # ---- Hard signals (apply even to "trusted" looking URLs) ----
    if features["has_ip"] or _HEX_IP_RE.match(host):
        score += 45
        reasons.append("The link points to a raw IP address instead of a real domain name.")
    if features["has_at_symbol"]:
        score += 25
        reasons.append("The URL contains '@', which can hide the real destination.")
        userinfo = url.split("://", 1)[-1].split("@", 1)[0]
        if "." in userinfo and "/" not in userinfo:
            score += 35
            reasons.append(f"Text before '@' ('{userinfo}') looks like a website name, but the link really goes to '{hostname}'.")
    if "xn--" in host:
        score += 40
        reasons.append("The domain uses punycode (xn--), often used for look-alike (homograph) attacks.")
    elif any(ord(c) > 127 for c in host):
        score += 40
        reasons.append("The domain contains non-English look-alike characters.")

    if trusted:
        # Official domain over HTTPS: nothing else should push this up.
        reasons.insert(0, f"The domain '{rd}' is a recognised official/popular website.")
        return {"score": min(score, 100.0), "reasons": reasons, "trusted": True}

    # ---- Brand impersonation ----
    label_tokens = set(re.split(r"[-.\d_]+", f"{subdomain}.{domain_label}".strip(".")))
    domain_tokens = [t for t in re.split(r"[-_.]+", domain_label) if t]
    brand_hit = None

    for brand, domains in BRANDS.items():
        if rd in domains:
            continue
        # (a) exact official domain written inside a different domain: paypal.com.evil.ru
        for d in domains:
            if d in host and not (host == d or host.endswith("." + d)):
                brand_hit = (brand, "embedded")
                break
        if brand_hit:
            break
        # (b) brand as its own token or long brand as a substring
        sk_label = _skeleton(domain_label)
        if brand in domain_tokens or brand in label_tokens or (len(brand) >= 6 and brand in domain_label.lower()):
            brand_hit = (brand, "contains")
            break
        # (c) typosquatting / homoglyph on the main label
        sk_brand = _skeleton(brand)
        if len(brand) >= 5:
            if sk_label == sk_brand and domain_label.lower() != brand:
                brand_hit = (brand, "lookalike")
                break
            dist = _levenshtein(domain_label.lower(), brand)
            if dist <= (1 if len(brand) < 8 else 2) and domain_label.lower() != brand:
                brand_hit = (brand, "typo")
                break
        # (d) brand-in-subdomain: apple.fake-site.com / login.paypal.fake.com
        if subdomain and (brand in subdomain.lower().split(".") or (len(brand) >= 6 and brand in subdomain.lower())):
            brand_hit = (brand, "subdomain")
            break
        # token-level typo, e.g. 'paypa1-secure'
        for tok in domain_tokens:
            if len(brand) >= 5 and len(tok) >= 5 and _skeleton(tok) == sk_brand and tok != brand:
                brand_hit = (brand, "lookalike")
                break
        if brand_hit:
            break

    if brand_hit:
        brand, kind = brand_hit
        official_list = ", ".join(BRANDS[brand][:2])
        if kind == "embedded":
            score += 65
            reasons.append(f"The real '{brand}' domain is written inside a different website's address (a classic trick). Official site: {official_list}.")
        elif kind in ("lookalike", "typo"):
            score += 70
            reasons.append(f"The domain '{rd}' imitates '{brand}' with look-alike spelling. Official site: {official_list}.")
        else:
            score += 55
            reasons.append(f"The URL uses the name '{brand}' but is NOT the official website. Official site: {official_list}.")

    # ---- Generic signals ----
    tld = suffix.split(".")[-1] if suffix else ""
    if tld in RISKY_TLDS:
        score += 14
        reasons.append(f"The domain ends in '.{tld}', a TLD very commonly abused for phishing.")
    if rd in SHORTENERS:
        score += 40
        reasons.append("This is a URL shortener; the real destination is hidden.")
    if scheme != "https":
        score += 10
        reasons.append("The site does not use HTTPS.")

    kw_total, kws = 0, []
    for w, pts in PHISH_WORDS.items():
        if w in full_lower:
            kw_total += pts
            kws.append(w)
    if kws:
        # keywords on an unverified domain matter; cap the effect
        kw_score = min(kw_total, 24)
        score += kw_score
        reasons.append(f"The URL contains phishing-style words: {', '.join(kws[:5])}.")

    if features["num_hyphens"] >= 3:
        score += 8
        reasons.append("The address contains many hyphens, typical of fake look-alike domains.")
    if features["num_subdomains"] >= 3:
        score += 8
        reasons.append("The address has an unusually large number of subdomains.")
    if features["url_length"] > 100:
        score += 6
        reasons.append("The URL is unusually long.")
    if domain_label and sum(c.isdigit() for c in domain_label) >= 3:
        score += 6
        reasons.append("The domain name contains many digits.")
    if features["entropy"] > 3.9 and len(domain_label) >= 12:
        score += 8
        reasons.append("The domain name looks randomly generated.")

    return {"score": min(score, 100.0), "reasons": reasons, "trusted": False}
