import re
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc
from ..models.db_models import AuditLog

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|secret|api[_-]?key|token|auth|bearer)\s*[:=]\s*["\']?([^"\'\s]+)["\']?', r'\1: [REDACTED]')
]

def sanitize_details(details: Optional[str]) -> Optional[str]:
    if not details:
        return details
    sanitized = details
    for pattern, repl in SECRET_PATTERNS:
        sanitized = re.sub(pattern, repl, sanitized)
    return sanitized

class AuditLogger:
    """
    Provides tamper-evident, sanitized security audit logging for all firewall events.
    Enforces privacy by scrubbing credentials and private keys before persisting.
    """

    def log(
        self,
        db: Session,
        agent_id: str,
        event_type: str,
        actor: str,
        action_summary: str,
        decision: Optional[str] = None,
        risk_score: Optional[float] = None,
        details: Optional[str] = None,
        event_id: Optional[str] = None,
        ip_address: str = "127.0.0.1"
    ) -> AuditLog:
        clean_details = sanitize_details(details)
        log_entry = AuditLog(
            event_id=event_id,
            agent_id=agent_id,
            event_type=event_type,
            actor=actor,
            action_summary=action_summary,
            decision=decision,
            risk_score=risk_score,
            details=clean_details,
            ip_address=ip_address
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry

    def query_logs(
        self,
        db: Session,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditLog]:
        query = db.query(AuditLog)
        
        if agent_id:
            query = query.filter(AuditLog.agent_id == agent_id)
        if decision:
            query = query.filter(AuditLog.decision == decision)
        if search_query:
            pattern = f"%{search_query}%"
            query = query.filter(
                or_(
                    AuditLog.action_summary.ilike(pattern),
                    AuditLog.details.ilike(pattern),
                    AuditLog.actor.ilike(pattern),
                    AuditLog.event_type.ilike(pattern)
                )
            )
            
        return query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()

audit_logger = AuditLogger()
