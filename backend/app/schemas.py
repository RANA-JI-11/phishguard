from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr


# ---------- Auth ----------
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    preferred_language: Optional[str] = "en"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: EmailStr
    full_name: Optional[str]
    plan: str
    preferred_language: str

    class Config:
        from_attributes = True


# ---------- Scan ----------
class ScanRequest(BaseModel):
    url: str
    language: Optional[str] = None  # overrides user's preferred_language for this call


class BulkScanRequest(BaseModel):
    urls: List[str]
    language: Optional[str] = None


class ScanResult(BaseModel):
    url: str
    verdict: str                 # safe / suspicious / phishing
    risk_score: float            # 0-100
    ml_confidence: float
    risk_factors: List[str]
    ai_explanation: str
    checked_at: str


class BulkScanResponse(BaseModel):
    results: List[ScanResult]


# ---------- API keys ----------
class ApiKeyOut(BaseModel):
    id: str
    key: str
    label: str
    is_active: bool

    class Config:
        from_attributes = True


class ApiKeyCreate(BaseModel):
    label: Optional[str] = "default"


# ---------- Alerts ----------
class AlertConfigCreate(BaseModel):
    channel: str          # slack / email / webhook
    target: str
    min_risk_score: float = 70.0


# ---------- Agent chat ----------
class AgentChatRequest(BaseModel):
    message: str
    url: Optional[str] = None       # context URL if the chat is about a specific scan
    language: Optional[str] = None


class AgentChatResponse(BaseModel):
    reply: str


# ---------- Billing ----------
class CheckoutRequest(BaseModel):
    plan: str  # "pro" or "business"
