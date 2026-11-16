# PhishGuard AI — API Reference (for frontend integration)

Base URL (local dev): `http://localhost:8000`
Interactive docs (always up to date, auto-generated): `/docs` and `/redoc`

## Authentication

Two ways to authenticate — use whichever fits the surface you're building:

| Method | Header | Use case |
|---|---|---|
| JWT | `Authorization: Bearer <token>` | Web dashboard, mobile app (user logs in) |
| API Key | `X-API-Key: <key>` | Browser extension, third-party developer integrations |

Every new signup automatically gets one free API key.

---

## Auth

### `POST /auth/signup`
```json
{ "email": "user@example.com", "password": "secret123", "full_name": "Jane Doe", "preferred_language": "en" }
```
→ Returns the created user object.

### `POST /auth/login`
```json
{ "email": "user@example.com", "password": "secret123" }
```
→ `{ "access_token": "...", "token_type": "bearer" }`

### `GET /auth/me`  *(auth required)*
→ Current user profile.

---

## Scanning (the core feature)

### `POST /scan`  *(auth required)*
```json
{ "url": "http://example-login-verify.com", "language": "en" }
```
→
```json
{
  "url": "...",
  "verdict": "phishing | suspicious | safe",
  "risk_score": 87.5,
  "ml_confidence": 91.2,
  "risk_factors": ["The link uses a raw IP address...", "..."],
  "ai_explanation": "This link looks risky because...",
  "checked_at": "2026-09-12T10:00:00"
}
```

### `POST /scan/bulk`  *(auth required, Pro/Business plan only)*
```json
{ "urls": ["https://a.com", "https://b.com"] }
```
→ `{ "results": [ ...same shape as above per URL... ] }`

### `POST /scan/public-demo`  *(no auth — for a marketing landing page "try it" box)*
Same request/response shape as `/scan`. Rate-limit this at your CDN/reverse proxy.

### `POST /scan/qr`  *(auth required, multipart/form-data)*
Upload field name: `file` (an image containing a QR code). Decodes the QR
code and scans the embedded URL.

### `POST /scan/email`  *(auth required)*
```json
{ "email_text": "Dear user, verify your account here: http://fake-bank.com/login ..." }
```
→ Extracts every URL found in the pasted email and scans each one.

---

## History & Dashboard

### `GET /history?limit=50`  *(auth required)*
→ List of past scans for the current user.

### `GET /history/stats`  *(auth required)*
→ `{ "total_scans": N, "by_verdict": {...}, "daily_trend": [...], "plan": "free" }`
Use this to power charts on the dashboard.

---

## API Keys

### `POST /api-keys` *(auth required, body: `{ "label": "my-extension" }`)*
### `GET /api-keys` *(auth required)*
### `DELETE /api-keys/{key_id}` *(auth required)*

---

## AI Agent Chat

### `POST /agent/chat`  *(auth required)*
```json
{ "message": "Is it safe to enter my password on this site?", "url": "https://...", "language": "en" }
```
→ `{ "reply": "..." }`

---

## Alerts

### `POST /alerts`  *(auth required)*
```json
{ "channel": "slack", "target": "https://hooks.slack.com/...", "min_risk_score": 70 }
```
`channel` can be `slack`, `email`, or `webhook`.

### `GET /alerts` *(auth required)*

---

## Teams (Business plan)

### `POST /team`  *(body: `{ "name": "Security Team" }`)*
### `POST /team/invite`  *(body: `{ "email": "colleague@company.com" }`)*
### `GET /team/history`  — shared scan history across the team

---

## Billing (Stripe)

### `GET /billing/plans`  *(public)* — pricing table, read this for your pricing page
### `POST /billing/checkout`  *(auth required, body: `{ "plan": "pro" }`)*
→ `{ "checkout_url": "https://checkout.stripe.com/..." }` — redirect the user here
### `POST /billing/webhook` — Stripe calls this automatically, don't call it from the frontend

---

## Error format

All errors follow FastAPI's standard shape:
```json
{ "detail": "Human-readable error message" }
```
Common status codes: `401` (not authenticated), `403` (plan doesn't allow this),
`429` (daily scan limit reached — prompt the user to upgrade).
