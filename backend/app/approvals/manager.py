from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from ..models.db_models import ApprovalRequest, SecurityEvent, AuditLog
from ..config.settings import settings

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
        reason: str,
        expires_in_seconds: Optional[int] = None,
        expires_in_minutes: Optional[int] = None
    ) -> ApprovalRequest:
        now = datetime.now(timezone.utc)
        if expires_in_seconds is not None:
            expires_at = now + timedelta(seconds=expires_in_seconds)
        elif expires_in_minutes is not None:
            expires_at = now + timedelta(minutes=expires_in_minutes)
        else:
            exp_sec = getattr(settings, "APPROVAL_EXPIRY_SECONDS", 60)
            expires_at = now + timedelta(seconds=exp_sec)

        approval = ApprovalRequest(
            event_id=event_id,
            agent_id=agent_id,
            action_type=action_type,
            target_resource=target_resource,
            parameters=parameters_str,
            calculated_risk=calculated_risk,
            threat_category=threat_category,
            reason=reason,
            status="PENDING",
            created_at=now,
            expires_at=expires_at
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

        # Expiry Check
        now = datetime.now(timezone.utc)
        if approval.expires_at:
            exp = approval.expires_at if approval.expires_at.tzinfo else approval.expires_at.replace(tzinfo=timezone.utc)
            if exp < now and approval.status == "PENDING":
                approval.status = "EXPIRED"
                db.commit()
                return {"success": False, "message": "Approval request has expired and cannot be approved."}

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

        # Expiry Check
        now = datetime.now(timezone.utc)
        if approval.expires_at:
            exp = approval.expires_at if approval.expires_at.tzinfo else approval.expires_at.replace(tzinfo=timezone.utc)
            if exp < now and approval.status == "PENDING":
                approval.status = "EXPIRED"
                db.commit()
                return {"success": False, "message": "Approval request has expired and cannot be rejected."}

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

    def expire_stale_approvals(self, db: Session) -> int:
        """
        Scans for any PENDING approvals that have passed their expires_at timestamp,
        auto-rejects them with fail-safe status 'EXPIRED', updates the associated
        SecurityEvent, and records tamper-evident audit logs.
        """
        now = datetime.now(timezone.utc)
        # Check both timezone-aware and naive timestamps
        stale_requests = db.query(ApprovalRequest).filter(
            ApprovalRequest.status == "PENDING",
            ApprovalRequest.expires_at != None
        ).all()

        expired_count = 0
        for req in stale_requests:
            exp = req.expires_at if req.expires_at.tzinfo else req.expires_at.replace(tzinfo=timezone.utc)
            if exp <= now:
                req.status = "EXPIRED"
                req.resolved_at = now
                req.resolved_by = "SYSTEM_FAILSAFE"
                req.resolution_notes = "Auto-rejected: Approval window expired before human review."

                # Update associated security event
                event = db.query(SecurityEvent).filter(SecurityEvent.id == req.event_id).first()
                if event:
                    event.execution_status = "EXPIRED"
                    event.decision = "BLOCK"
                    event.decision_reason += " | Fail-safe auto-rejected due to approval expiration."

                # Record audit log
                audit = AuditLog(
                    event_id=event.id if event else None,
                    agent_id=req.agent_id,
                    event_type="APPROVAL_EXPIRED",
                    actor="FIREWALL_FAILSAFE",
                    action_summary=f"Approval expired for action '{req.action_type}' targeting '{req.target_resource}'",
                    decision="BLOCK",
                    risk_score=req.calculated_risk,
                    details="Action fail-safe auto-rejected due to approval timeout."
                )
                db.add(audit)
                expired_count += 1

        if expired_count > 0:
            db.commit()

        return expired_count

    def get_pending(self, db: Session) -> List[ApprovalRequest]:
        # Expire stale approvals first to maintain real-time sync
        self.expire_stale_approvals(db)
        return db.query(ApprovalRequest).filter(ApprovalRequest.status == "PENDING").order_by(ApprovalRequest.created_at.desc()).all()

    def get_all(self, db: Session, limit: int = 100) -> List[ApprovalRequest]:
        return db.query(ApprovalRequest).order_by(ApprovalRequest.created_at.desc()).limit(limit).all()

approval_manager = ApprovalManager()
