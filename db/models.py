import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, JSON, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class SecurityIncident(Base):
    """
    Forensic record of blocked attacks and high-risk security incidents.
    Persisted in PostgreSQL for compliance, auditing, and SOC investigation.
    """
    __tablename__ = "security_incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    request_id = Column(String(64), index=True)
    user_id = Column(String(128), index=True)
    client_ip = Column(String(45))
    endpoint = Column(String(256))
    http_method = Column(String(10))
    risk_score = Column(Float, nullable=False)
    threat_type = Column(String(64), nullable=False, index=True)
    threat_indicators = Column(JSON, default=list)
    action_taken = Column(String(32), nullable=False)  # BLOCKED, TARPIT, REVOKED
    features_snapshot = Column(JSON, default=dict)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "request_id": self.request_id,
            "user_id": self.user_id,
            "client_ip": self.client_ip,
            "endpoint": self.endpoint,
            "http_method": self.http_method,
            "risk_score": self.risk_score,
            "threat_type": self.threat_type,
            "threat_indicators": self.threat_indicators,
            "action_taken": self.action_taken,
            "features_snapshot": self.features_snapshot
        }


class BlockedEntity(Base):
    """
    Entities (Users or IPs) blocked from accessing the gateway.
    """
    __tablename__ = "blocked_entities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_type = Column(String(16), nullable=False)  # USER or IP
    entity_value = Column(String(128), nullable=False, index=True)
    reason = Column(String(256), nullable=False)
    blocked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "reason": self.reason,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active
        }


class TelemetryLog(Base):
    """
    Continuous telemetry log of normal and anomalous requests for behavioral analytics.
    """
    __tablename__ = "telemetry_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    user_id = Column(String(128), index=True)
    endpoint = Column(String(256))
    risk_score = Column(Float, nullable=False)
    latency_ms = Column(Float, nullable=False)
    status_code = Column(Integer, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_id": self.user_id,
            "endpoint": self.endpoint,
            "risk_score": self.risk_score,
            "latency_ms": self.latency_ms,
            "status_code": self.status_code
        }

