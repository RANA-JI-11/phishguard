import uuid
import datetime as dt

from sqlalchemy import (
    Column, String, Boolean, Integer, Float, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    preferred_language = Column(String, default="en")  # en, hi, es, fr ...
    plan = Column(String, default="free")  # free / pro / business
    stripe_customer_id = Column(String, nullable=True)
    team_id = Column(UUID(as_uuid=False), ForeignKey("teams.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    api_keys = relationship("ApiKey", back_populates="owner")
    scans = relationship("ScanHistory", back_populates="user")
    alerts = relationship("AlertConfig", back_populates="user")


class Team(Base):
    __tablename__ = "teams"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    owner_email = Column(String, nullable=False)
    plan = Column(String, default="business")
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    members = relationship("User", backref="team", foreign_keys=[User.team_id])


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    key = Column(String, unique=True, index=True, nullable=False)
    label = Column(String, default="default")
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="api_keys")


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    url = Column(Text, nullable=False)
    verdict = Column(String)          # safe / suspicious / phishing
    risk_score = Column(Float)        # 0-100
    ml_confidence = Column(Float)
    risk_factors = Column(JSON)       # list of reasons
    ai_explanation = Column(Text)     # AI agent's plain-language explanation
    source = Column(String, default="api")  # api / extension / email / qr / dashboard
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    user = relationship("User", back_populates="scans")


class AlertConfig(Base):
    __tablename__ = "alert_configs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    channel = Column(String)   # slack / email / webhook
    target = Column(String)    # slack webhook url / email address / custom webhook url
    min_risk_score = Column(Float, default=70.0)
    is_active = Column(Boolean, default=True)

    user = relationship("User", back_populates="alerts")


class UsageLog(Base):
    """Used for daily rate-limiting per plan and for billing/metering."""
    __tablename__ = "usage_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    date = Column(String, index=True)  # YYYY-MM-DD
    scan_count = Column(Integer, default=0)


class ThreatIntelCache(Base):
    """Cache of external threat-intel lookups (Google Safe Browsing, VirusTotal, WHOIS)
    to avoid re-paying/re-calling for the same domain repeatedly."""
    __tablename__ = "threat_intel_cache"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    domain = Column(String, unique=True, index=True)
    data = Column(JSON)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)
