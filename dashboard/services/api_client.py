import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import requests

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.database.connection import SessionLocal, init_db
from backend.app.models.db_models import Agent, SecurityEvent, ApprovalRequest, SecurityPolicy, AuditLog
from backend.app.policies.policy_engine import policy_engine
from backend.app.approvals.manager import approval_manager
from backend.app.firewall.engine import firewall_engine
from backend.app.logging.audit_logger import audit_logger
from backend.app.schemas.firewall_schemas import FirewallCheckRequest, ContextTaintInfo, OriginType

API_BASE_URL = os.getenv("FIREWALL_API_URL", "http://127.0.0.1:8000/api/v1")

class SecurityDashboardService:
    """
    Data service layer for the Streamlit Security Dashboard.
    Directly interfaces with SQLite database models and local security engines
    to ensure 100% genuine data metrics without artificial delays or network dependencies.
    """

    def __init__(self):
        init_db()

    def get_db(self):
        return SessionLocal()

    def get_statistics(self) -> Dict[str, Any]:
        db = self.get_db()
        try:
            total_inspections = db.query(SecurityEvent).count()
            allowed_actions = db.query(SecurityEvent).filter(SecurityEvent.decision == "ALLOW").count()
            blocked_threats = db.query(SecurityEvent).filter(SecurityEvent.decision == "BLOCK").count()
            pending_approvals = db.query(ApprovalRequest).filter(ApprovalRequest.status == "PENDING").count()

            threat_detected_count = db.query(SecurityEvent).filter(SecurityEvent.threat_detected == True).count()
            threat_detection_rate = (threat_detected_count / total_inspections * 100) if total_inspections > 0 else 0.0

            # False Positive Calculation
            fp_count = db.query(SecurityEvent).filter(
                SecurityEvent.decision == "BLOCK",
                SecurityEvent.threat_detected == False
            ).count()
            tn_count = db.query(SecurityEvent).filter(
                SecurityEvent.decision == "ALLOW",
                SecurityEvent.threat_detected == False
            ).count()
            fpr = (fp_count / (fp_count + tn_count) * 100) if (fp_count + tn_count) > 0 else 0.0

            all_events = db.query(SecurityEvent).all()
            avg_risk = sum(e.calculated_risk for e in all_events) / max(len(all_events), 1)

            return {
                "total_inspections": total_inspections,
                "allowed_actions": allowed_actions,
                "blocked_threats": blocked_threats,
                "pending_approvals": pending_approvals,
                "threat_detection_rate": round(threat_detection_rate, 1),
                "false_positive_rate": round(fpr, 2),
                "avg_risk_score": round(avg_risk, 3)
            }
        finally:
            db.close()

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        db = self.get_db()
        try:
            events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
            result = []
            for e in events:
                result.append({
                    "id": e.id,
                    "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "N/A",
                    "agent_id": e.agent_id,
                    "action_type": e.action_type,
                    "target_resource": e.target_resource,
                    "threat_detected": e.threat_detected,
                    "threat_category": e.threat_category or "NONE",
                    "threat_severity": e.threat_severity or "NONE",
                    "calculated_risk": round(e.calculated_risk, 2),
                    "decision": e.decision,
                    "decision_reason": e.decision_reason,
                    "execution_status": e.execution_status
                })
            return result
        finally:
            db.close()

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        db = self.get_db()
        try:
            approvals = db.query(ApprovalRequest).filter(ApprovalRequest.status == "PENDING").order_by(ApprovalRequest.created_at.desc()).all()
            res = []
            for a in approvals:
                res.append({
                    "id": a.id,
                    "event_id": a.event_id,
                    "agent_id": a.agent_id,
                    "action_type": a.action_type,
                    "target_resource": a.target_resource,
                    "parameters": a.parameters,
                    "calculated_risk": round(a.calculated_risk, 2),
                    "threat_category": a.threat_category or "ELEVATED_RISK",
                    "reason": a.reason,
                    "status": a.status,
                    "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S") if a.created_at else "N/A"
                })
            return res
        finally:
            db.close()

    def approve_action(self, approval_id: str, reviewer: str = "security_officer", notes: str = "") -> Dict[str, Any]:
        db = self.get_db()
        try:
            return approval_manager.approve(db, approval_id, reviewer=reviewer, notes=notes)
        finally:
            db.close()

    def reject_action(self, approval_id: str, reviewer: str = "security_officer", notes: str = "") -> Dict[str, Any]:
        db = self.get_db()
        try:
            return approval_manager.reject(db, approval_id, reviewer=reviewer, notes=notes)
        finally:
            db.close()

    def get_audit_logs(self, search: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        db = self.get_db()
        try:
            logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
            res = []
            for l in logs:
                if search:
                    s_low = search.lower()
                    match = (s_low in l.action_summary.lower() or 
                             (l.details and s_low in l.details.lower()) or 
                             s_low in l.actor.lower() or 
                             s_low in l.event_type.lower())
                    if not match:
                        continue
                res.append({
                    "id": l.id,
                    "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if l.timestamp else "N/A",
                    "event_id": l.event_id or "-",
                    "agent_id": l.agent_id,
                    "event_type": l.event_type,
                    "actor": l.actor,
                    "action_summary": l.action_summary,
                    "action": l.action_summary,  # backward compatibility alias
                    "decision": l.decision or "-",
                    "risk_score": f"{l.risk_score:.2f}" if l.risk_score is not None else "-",
                    "prev_hash": l.prev_hash or "GENESIS",
                    "row_hash": l.row_hash or "-",
                    "ip_address": l.ip_address or "127.0.0.1",
                    "details": l.details or ""
                })
            return res
        finally:
            db.close()

    def verify_audit_chain(self) -> Dict[str, Any]:
        db = self.get_db()
        try:
            return audit_logger.verify_chain(db)
        finally:
            db.close()

    def get_policy_yaml(self) -> str:
        return policy_engine.get_raw_yaml()

    def update_policy_yaml(self, content_yaml: str) -> Dict[str, Any]:
        db = self.get_db()
        try:
            updated = policy_engine.update_policy(content_yaml)
            db_policy = SecurityPolicy(
                version="1.1",
                content_yaml=content_yaml,
                is_active=True
            )
            db.add(db_policy)
            db.commit()
            return {"success": True, "policy": updated}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            db.close()

dashboard_service = SecurityDashboardService()
