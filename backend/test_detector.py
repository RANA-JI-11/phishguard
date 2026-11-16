"""Run:  python test_detector.py   (no database / internet needed)"""
from app.ml.predictor import predict_url

CASES = [  # (url, expected)  expected: safe | phishing | not_safe
    ("https://www.google.com", "safe"), ("https://accounts.google.com/signin", "safe"),
    ("https://www.sbi.co.in", "safe"), ("https://netbanking.hdfcbank.com", "safe"),
    ("https://www.amazon.in", "safe"), ("https://github.com/login", "safe"),
    ("http://paypa1-secure-login.xyz/verify", "phishing"), ("https://paypal.com.evil-site.ru/login", "phishing"),
    ("https://secure-hdfcbank-update.top/kyc", "phishing"), ("https://netfIix-billing.com/update", "phishing"),
    ("http://sbi-kyc-update.in/login", "phishing"), ("https://amaz0n.in/signin", "phishing"),
    ("http://192.168.1.5/login", "phishing"), ("https://google.com@evil.com/login", "phishing"),
    ("https://xn--pple-43d.com", "not_safe"), ("bit.ly/3abcde", "not_safe"),
]
fails = 0
for url, exp in CASES:
    r = predict_url(url)
    ok = (r["verdict"] != "safe") if exp == "not_safe" else (r["verdict"] == exp)
    fails += not ok
    print("PASS" if ok else "FAIL", f"{r['verdict']:10}{r['risk_score']:6}", url)
print(f"\n{len(CASES)-fails}/{len(CASES)} passed")
