import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Integer,
    Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def get_utc_now():
    return datetime.now(timezone.utc)

class Agent(Base):
    __tablename__ = "agents"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    description = Column(String(256), nullable=True)
    role = Column(String(64), default="assistant")
    trust_level = Column(Float, default=0.5)  # 0.0 to 1.0
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=get_utc_now)
    
    events = relationship("SecurityEvent", back_populates="agent", cascade="all, delete-orphan")

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(64), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=get_utc_now, index=True)
    agent_id = Column(String(64), ForeignKey("agents.id"), index=True, nullable=False)
    session_id = Column(String(64), index=True, nullable=True)
    
    # Action under inspection
    action_type = Column(String(64), index=True, nullable=False)
    target_resource = Column(String(256), nullable=False)
    parameters = Column(Text, nullable=True)  # JSON string
    
    # Detection & Taint analysis
    threat_detected = Column(Boolean, default=False, index=True)
    threat_category = Column(String(64), nullable=True, index=True)
    threat_severity = Column(String(32), nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    threat_details = Column(Text, nullable=True)  # JSON or text description
    
    taint_source = Column(String(64), nullable=True)  # USER, SYSTEM, WEBPAGE, FILE, API, TOOL_OUTPUT
    is_tainted = Column(Boolean, default=False, index=True)
    
    # Normalized risk metrics (0.0 to 1.0)
    action_severity = Column(Float, nullable=False, default=0.5)
    target_trust = Column(Float, nullable=False, default=0.5)
    data_sensitivity = Column(Float, nullable=False, default=0.5)
    calculated_risk = Column(Float, nullable=False, index=True)
    
    # Decision Engine result
    decision = Column(String(32), nullable=False, index=True)  # ALLOW, ASK_HUMAN, BLOCK
    decision_reason = Column(Text, nullable=False)
    
    # Execution tracking
    execution_status = Column(String(32), default="PENDING", index=True)  # PENDING, EXECUTED, BLOCKED, REJECTED
    execution_result = Column(Text, nullable=True)
    
    agent = relationship("Agent", back_populates="events")
    approval_request = relationship("ApprovalRequest", uselist=False, back_populates="event", cascade="all, delete-orphan")

class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id = Column(String(64), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(64), ForeignKey("security_events.id"), unique=True, index=True, nullable=False)
    agent_id = Column(String(64), nullable=False, index=True)
    
    action_type = Column(String(64), nullable=False)
    target_resource = Column(String(256), nullable=False)
    parameters = Column(Text, nullable=True)
    
    calculated_risk = Column(Float, nullable=False)
    threat_category = Column(String(64), nullable=True)
    reason = Column(Text, nullable=False)
    
    status = Column(String(32), default="PENDING", index=True)  # PENDING, APPROVED, REJECTED, EXPIRED
    created_at = Column(DateTime, default=get_utc_now, index=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(64), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    event = relationship("SecurityEvent", back_populates="approval_request")

class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(String(32), nullable=False)
    content_yaml = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=get_utc_now)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=get_utc_now, index=True)
    event_id = Column(String(64), nullable=True, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    actor = Column(String(32), nullable=False)  # AGENT, FIREWALL, HUMAN_ADMIN, SYSTEM
    action_summary = Column(String(256), nullable=False)
    decision = Column(String(32), nullable=True)
    risk_score = Column(Float, nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(64), default="127.0.0.1")

# Indexes for fast querying
Index("ix_security_events_time_decision", SecurityEvent.timestamp, SecurityEvent.decision)
Index("ix_audit_logs_time_event", AuditLog.timestamp, AuditLog.event_type)
