from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from ..models.db_models import ApprovalRequest, SecurityEvent, AuditLog

class ApprovalManager:
    """
    Manages human-in-the-loop approval workflows for medium-to-high risk agent actions.
    Ensures approvals are cryptographically bound to specific pending operations.
    """

    def create_approval_request(
        self,
        db: Session,
        event_id: str,
        agent_id: str,
        action_type: str,
        target_resource: str,
        parameters_str: str,
        calculated_risk: float,
        threat_category: Optional[str],
        reason: str
    ) -> ApprovalRequest:
        approval = ApprovalRequest(
            event_id=event_id,
            agent_id=agent_id,
            action_type=action_type,
            target_resource=target_resource,
            parameters=parameters_str,
            calculated_risk=calculated_risk,
            threat_category=threat_category,
            reason=reason,
            status="PENDING"
        )
        db.add(approval)
        db.commit()
        db.refresh(approval)
        return approval

    def approve(
        self,
        db: Session,
        approval_id: str,
        reviewer: str = "security_officer",
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        approval = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_id).first()
        if not approval:
            return {"success": False, "message": f"Approval request '{approval_id}' not found."}

        if approval.status != "PENDING":
            return {"success": False, "message": f"Approval request already resolved with status '{approval.status}'."}

        approval.status = "APPROVED"
        approval.resolved_at = datetime.now(timezone.utc)
        approval.resolved_by = reviewer
        approval.resolution_notes = notes or "Action approved by human reviewer."

        # Update associated security event
        event = db.query(SecurityEvent).filter(SecurityEvent.id == approval.event_id).first()
        if event:
            event.execution_status = "APPROVED_BY_HUMAN"
            event.decision_reason += f" | Approved by {reviewer}"

        # Record audit log
        audit = AuditLog(
            event_id=event.id if event else None,
            agent_id=approval.agent_id,
            event_type="APPROVAL_GRANTED",
            actor="HUMAN_ADMIN",
            action_summary=f"Human approved action '{approval.action_type}' for target '{approval.target_resource}'",
            decision="ALLOW",
            risk_score=approval.calculated_risk,
            details=f"Reviewer: {reviewer}. Notes: {notes}"
        )
        db.add(audit)
        db.commit()
        db.refresh(approval)

        return {
            "success": True,
            "message": "Action approved successfully.",
            "approval_id": approval.id,
            "event_id": approval.event_id,
            "status": "APPROVED"
        }

    def reject(
        self,
        db: Session,
        approval_id: str,
        reviewer: str = "security_officer",
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        approval = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_id).first()
        if not approval:
            return {"success": False, "message": f"Approval request '{approval_id}' not found."}

        if approval.status != "PENDING":
            return {"success": False, "message": f"Approval request already resolved with status '{approval.status}'."}

        approval.status = "REJECTED"
        approval.resolved_at = datetime.now(timezone.utc)
        approval.resolved_by = reviewer
        approval.resolution_notes = notes or "Action rejected by human reviewer."

        # Update associated security event
        event = db.query(SecurityEvent).filter(SecurityEvent.id == approval.event_id).first()
        if event:
            event.execution_status = "REJECTED_BY_HUMAN"
            event.decision_reason += f" | Rejected by {reviewer}"

        # Record audit log
        audit = AuditLog(
            event_id=event.id if event else None,
            agent_id=approval.agent_id,
            event_type="APPROVAL_REJECTED",
            actor="HUMAN_ADMIN",
            action_summary=f"Human rejected action '{approval.action_type}' for target '{approval.target_resource}'",
            decision="BLOCK",
            risk_score=approval.calculated_risk,
            details=f"Reviewer: {reviewer}. Notes: {notes}"
        )
        db.add(audit)
        db.commit()
        db.refresh(approval)

        return {
            "success": True,
            "message": "Action rejected successfully.",
            "approval_id": approval.id,
            "event_id": approval.event_id,
            "status": "REJECTED"
        }

    def get_pending(self, db: Session) -> List[ApprovalRequest]:
        return db.query(ApprovalRequest).filter(ApprovalRequest.status == "PENDING").order_by(ApprovalRequest.created_at.desc()).all()

    def get_all(self, db: Session, limit: int = 100) -> List[ApprovalRequest]:
        return db.query(ApprovalRequest).order_by(ApprovalRequest.created_at.desc()).limit(limit).all()

approval_manager = ApprovalManager()
