"""
External threat-intelligence checks. EVERY function is failure-safe: a timeout,
missing API key or no internet connection returns "unknown" (None) and never
raises, so one slow service can never crash a scan.

Sources:
  * OpenPhish community feed   - free, no API key (auto-refreshed hourly)
  * Google Safe Browsing       - needs GOOGLE_SAFE_BROWSING_API_KEY
  * VirusTotal                 - needs VIRUSTOTAL_API_KEY
  * WHOIS domain age, SSL certificate validity
"""
import base64
import ssl
import socket
import time
import threading
import datetime as dt
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

from app.config import settings

try:
    import whois as pywhois
except ImportError:  # pragma: no cover
    pywhois = None

# ---------------- OpenPhish feed (cached) ----------------
_OPENPHISH_URL = "https://openphish.com/feed.txt"
_feed_lock = threading.Lock()
_feed = {"urls": set(), "hosts": set(), "ts": 0.0}


def _load_openphish():
    now = time.time()
    if now - _feed["ts"] < 3600 and _feed["ts"] > 0:
        return
    with _feed_lock:
        if now - _feed["ts"] < 3600 and _feed["ts"] > 0:
            return
        try:
            r = requests.get(_OPENPHISH_URL, timeout=6, headers={"User-Agent": "PhishGuard/1.0"})
            r.raise_for_status()
            urls = {ln.strip().lower().rstrip("/") for ln in r.text.splitlines() if ln.strip()}
            hosts = {(urlparse(u).hostname or "") for u in urls}
            _feed.update(urls=urls, hosts=hosts, ts=time.time())
        except Exception:
            _feed["ts"] = time.time() - 3300  # retry in ~5 minutes instead of every request


def check_openphish(url: str, hostname: str):
    """True = listed, False = not listed, None = feed unavailable."""
    _load_openphish()
    if not _feed["urls"]:
        return None
    return url.lower().rstrip("/") in _feed["urls"] or hostname.lower() in _feed["hosts"]


# ---------------- Google Safe Browsing ----------------
def check_google_safe_browsing(url: str):
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return None
    endpoint = ("https://safebrowsing.googleapis.com/v4/threatMatches:find"
                f"?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}")
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=body, timeout=5)
        resp.raise_for_status()
        return bool(resp.json().get("matches"))
    except Exception:
        return None


# ---------------- VirusTotal ----------------
def check_virustotal(url: str):
    """Looks up an existing report (fast). True if >=3 engines say malicious/phishing."""
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    try:
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)
        if r.status_code == 404:  # never seen: submit for future lookups, result unknown now
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=8)
            return None
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return (stats.get("malicious", 0) + stats.get("suspicious", 0)) >= 3
    except Exception:
        return None


# ---------------- WHOIS / SSL ----------------
def get_domain_age_days(domain: str):
    if pywhois is None or not domain:
        return None
    try:
        w = pywhois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None
        if getattr(creation, "tzinfo", None) is not None:
            creation = creation.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return max((dt.datetime.utcnow() - creation).days, 0)
    except Exception:
        return None


def check_ssl_valid(hostname: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                pass
        return True
    except ssl.SSLCertVerificationError:
        return False
    except Exception:
        return None


def enrich(url: str, hostname: str, registered_domain: str) -> dict:
    """Runs all checks in parallel (max ~8s total) and returns a combined dict."""
    result = {"blacklisted": None, "blacklist_sources": [], "domain_age_days": None,
              "ssl_valid": None, "checks_run": []}
    jobs = {
        "OpenPhish": lambda: check_openphish(url, hostname),
        "Google Safe Browsing": lambda: check_google_safe_browsing(url),
        "VirusTotal": lambda: check_virustotal(url),
        "age": lambda: get_domain_age_days(registered_domain),
        "ssl": lambda: check_ssl_valid(hostname) if hostname else None,
    }
    try:
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {name: pool.submit(fn) for name, fn in jobs.items()}
            for name, fut in futures.items():
                try:
                    val = fut.result(timeout=9)
                except Exception:
                    val = None
                if name == "age":
                    result["domain_age_days"] = val
                elif name == "ssl":
                    result["ssl_valid"] = val
                elif val is not None:
                    result["checks_run"].append(name)
                    if val:
                        result["blacklist_sources"].append(name)
    except Exception:
        pass
    if result["checks_run"]:
        result["blacklisted"] = bool(result["blacklist_sources"])
    return result
