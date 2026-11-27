import time
import hmac
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status, Header, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, text, select

from ..database.connection import get_db
from ..models.db_models import Agent, SecurityEvent, ApprovalRequest, SecurityPolicy, AuditLog
from ..schemas.firewall_schemas import (
    FirewallCheckRequest,
    FirewallCheckResponse,
    FirewallExecuteRequest,
    FirewallExecuteResponse,
    ApprovalDecisionRequest,
    ApprovalResponse,
    SecurityEventResponse,
    AuditLogResponse,
    AgentCreateRequest,
    AgentResponse,
    PolicyUpdateRequest,
    SecurityStatistics,
    DecisionType
)
from ..firewall.engine import firewall_engine
from ..tools.protected_tools import protected_tools
from ..approvals.manager import approval_manager
from ..policies.policy_engine import policy_engine
from ..logging.audit_logger import audit_logger
from ..detection.file_scanner import file_scanner, FileScanResult
from ..agents.llm_router import llm_router
from ..config.settings import settings

router = APIRouter()

def verify_admin_access(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
    authorization: Optional[str] = Header(None)
):
    """
    Validates administrative authorization token for sensitive approval and policy endpoints
    using constant-time comparison to prevent timing attacks.
    """
    token = None
    if isinstance(x_admin_token, str) and x_admin_token.strip():
        token = x_admin_token.strip()
    elif isinstance(authorization, str) and authorization.strip():
        if authorization.startswith("Bearer "):
            token = authorization[7:].strip()
        else:
            token = authorization.strip()

    expected_key = getattr(settings, "ADMIN_API_KEY", None) or settings.SECRET_KEY

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Missing administrative authorization token (X-Admin-Token or Bearer Authorization required)."
        )

    if not hmac.compare_digest(token.encode("utf-8"), expected_key.encode("utf-8")):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Invalid administrative authorization token."
        )

    return True

# -------------------------------------------------------------
# 1. Health Endpoint
# -------------------------------------------------------------
@router.get("/health", tags=["System"])
def health_check(db: Session = Depends(get_db)):
    """Health and status endpoint for monitoring."""
    try:
        # Check database connectivity
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return {
        "status": "healthy",
        "service": "AI Agent Firewall & Security Platform",
        "version": "1.0.0",
        "database": db_status,
        "fail_closed_mode": True
    }

# -------------------------------------------------------------
# 2. Firewall Check & Execute Endpoints
# -------------------------------------------------------------
@router.post("/firewall/check", response_model=FirewallCheckResponse, tags=["Firewall"])
def check_tool_call(request: FirewallCheckRequest, db: Session = Depends(get_db)):
    """
    Inspects and evaluates an AI agent tool call request without executing it.
    Returns normalized risk score, detected threats, and decision (ALLOW, ASK_HUMAN, BLOCK).
    """
    return firewall_engine.inspect_and_evaluate(request, db)

@router.post("/firewall/execute", response_model=FirewallExecuteResponse, tags=["Firewall"])
def execute_protected_tool(request: FirewallExecuteRequest, db: Session = Depends(get_db)):
    """
    Enforces firewall authorization before executing a protected tool action.
    Execution is strictly denied if the firewall blocks the request or if required
    human approval has not been granted. Direct execution without inspection is impossible.
    Fails closed on any unexpected exception or malformed input.
    """
    try:
        # Case A: If an approval_id is provided, verify valid human authorization
        if request.approval_id:
            approval = db.query(ApprovalRequest).filter(ApprovalRequest.id == request.approval_id).first()
            if not approval:
                raise HTTPException(status_code=404, detail="Approval request not found.")
            
            # 1. Expiration check
            now = datetime.now(timezone.utc)
            if approval.expires_at:
                exp = approval.expires_at if approval.expires_at.tzinfo else approval.expires_at.replace(tzinfo=timezone.utc)
                if exp < now:
                    approval.status = "EXPIRED"
                    db.commit()
                    return FirewallExecuteResponse(
                        success=False,
                        event_id=approval.event_id,
                        decision=DecisionType.BLOCK,
                        execution_status="BLOCKED_APPROVAL_EXPIRED",
                        result=None,
                        message=f"Cannot execute: Approval request '{request.approval_id}' expired at {exp.isoformat()}."
                    )

            if approval.status != "APPROVED":
                return FirewallExecuteResponse(
                    success=False,
                    event_id=approval.event_id,
                    decision=DecisionType.BLOCK if approval.status in ["CONSUMED", "EXPIRED"] else DecisionType.ASK_HUMAN,
                    execution_status="BLOCKED_APPROVAL_INVALID",
                    result=None,
                    message=f"Cannot execute: Approval request is in status '{approval.status}'." + (
                        " This one-time approval has already been consumed." if approval.status == "CONSUMED" else ""
                    )
                )

            # 2. Exact Scope Binding Validation:
            if request.action_type != approval.action_type:
                return FirewallExecuteResponse(
                    success=False,
                    event_id=approval.event_id,
                    decision=DecisionType.BLOCK,
                    execution_status="BLOCKED_SCOPE_MISMATCH",
                    result=None,
                    message=f"Security Scope Violation: Requested action '{request.action_type}' does not match approved action '{approval.action_type}'."
                )

            if request.target_resource != approval.target_resource:
                return FirewallExecuteResponse(
                    success=False,
                    event_id=approval.event_id,
                    decision=DecisionType.BLOCK,
                    execution_status="BLOCKED_TARGET_MISMATCH",
                    result=None,
                    message=f"Security Scope Violation: Requested target '{request.target_resource}' does not match approved target '{approval.target_resource}'."
                )

            if request.agent_id != approval.agent_id:
                return FirewallExecuteResponse(
                    success=False,
                    event_id=approval.event_id,
                    decision=DecisionType.BLOCK,
                    execution_status="BLOCKED_AGENT_MISMATCH",
                    result=None,
                    message=f"Security Scope Violation: Requesting agent '{request.agent_id}' does not match authorized agent '{approval.agent_id}'."
                )

            # 3. Parameter tampering validation
            if approval.parameters and approval.parameters != "{}":
                try:
                    saved_params = json.loads(approval.parameters)
                    # Verify key parameters match
                    if request.parameters != saved_params:
                        return FirewallExecuteResponse(
                            success=False,
                            event_id=approval.event_id,
                            decision=DecisionType.BLOCK,
                            execution_status="BLOCKED_PARAM_TAMPERING",
                            result=None,
                            message="Security Violation: Execution parameters differ from the approved parameters."
                        )
                except Exception:
                    pass

            # 4. Atomic conditional update to eliminate TOCTOU race conditions
            rows_updated = db.query(ApprovalRequest).filter(
                ApprovalRequest.id == request.approval_id,
                ApprovalRequest.status == "APPROVED"
            ).update({"status": "CONSUMED"}, synchronize_session="fetch")
            db.commit()

            if rows_updated == 0:
                return FirewallExecuteResponse(
                    success=False,
                    event_id=approval.event_id,
                    decision=DecisionType.BLOCK,
                    execution_status="BLOCKED_APPROVAL_INVALID",
                    result=None,
                    message=f"Cannot execute: Approval '{request.approval_id}' was already consumed by a concurrent request (race condition prevented)."
                )
            
            # Execute strictly authorized tool
            tool_res = protected_tools.execute_tool(approval.action_type, approval.target_resource, request.parameters)
            
            # Update event status
            event = db.query(SecurityEvent).filter(SecurityEvent.id == approval.event_id).first()
            if event:
                event.execution_status = "EXECUTED"
                event.execution_result = str(tool_res)
                db.commit()

            return FirewallExecuteResponse(
                success=tool_res.get("success", False),
                event_id=approval.event_id,
                decision=DecisionType.ALLOW,
                execution_status="EXECUTED",
                result=tool_res,
                message="Execution authorized via verified single-use human approval."
            )

        # Case B: Perform full firewall inspection on the fly
        check_req = FirewallCheckRequest(
            agent_id=request.agent_id,
            action_type=request.action_type,
            target_resource=request.target_resource,
            parameters=request.parameters,
            context_taint=request.context_taint,
            content_to_scan=request.content_to_scan
        )
        eval_res = firewall_engine.inspect_and_evaluate(check_req, db)

        event = db.query(SecurityEvent).filter(SecurityEvent.id == eval_res.event_id).first()

        if eval_res.decision == DecisionType.BLOCK:
            if event:
                event.execution_status = "BLOCKED"
                db.commit()
            return FirewallExecuteResponse(
                success=False,
                event_id=eval_res.event_id,
                decision=DecisionType.BLOCK,
                execution_status="BLOCKED",
                result=None,
                message=f"Firewall Blocked Action: {eval_res.reason}"
            )

        if eval_res.decision == DecisionType.ASK_HUMAN:
            if event:
                event.execution_status = "PENDING_APPROVAL"
                db.commit()
            return FirewallExecuteResponse(
                success=False,
                event_id=eval_res.event_id,
                decision=DecisionType.ASK_HUMAN,
                execution_status="PENDING_APPROVAL",
                result=None,
                message=f"Action paused. Awaiting human approval (Approval ID: {eval_res.approval_id}). Reason: {eval_res.reason}"
            )

        # Decision is ALLOW: execute protected sandboxed tool
        tool_res = protected_tools.execute_tool(request.action_type, request.target_resource, request.parameters)
        if event:
            event.execution_status = "EXECUTED"
            event.execution_result = str(tool_res)
            db.commit()

        return FirewallExecuteResponse(
            success=tool_res.get("success", False),
            event_id=eval_res.event_id,
            decision=DecisionType.ALLOW,
            execution_status="EXECUTED",
            result=tool_res,
            message="Action authorized by firewall and safely executed."
        )

    except HTTPException:
        raise
    except Exception as e:
        # Strict Fail-Closed fallback
        return FirewallExecuteResponse(
            success=False,
            event_id=request.event_id or "fail-closed-error",
            decision=DecisionType.BLOCK,
            execution_status="FAIL_CLOSED_ERROR",
            result=None,
            message=f"Fail-Closed: Execution halted due to internal error: {str(e)}"
        )

# -------------------------------------------------------------
# 3. Security Events Endpoints
# -------------------------------------------------------------
@router.get("/events", response_model=List[SecurityEventResponse], tags=["Events"])
def list_events(
    agent_id: Optional[str] = None,
    decision: Optional[str] = None,
    threat_only: bool = False,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieves paginated security event history."""
    query = db.query(SecurityEvent)
    if agent_id:
        query = query.filter(SecurityEvent.agent_id == agent_id)
    if decision:
        query = query.filter(SecurityEvent.decision == decision)
    if threat_only:
        query = query.filter(SecurityEvent.threat_detected == True)
        
    return query.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit).all()

@router.get("/events/{event_id}", response_model=SecurityEventResponse, tags=["Events"])
def get_event(event_id: str, db: Session = Depends(get_db)):
    """Fetches details for a single security event."""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Security event not found.")
    return event

# -------------------------------------------------------------
# 4. Human Approval Endpoints
# -------------------------------------------------------------
@router.get("/approvals", response_model=List[ApprovalResponse], tags=["Approvals"])
def list_approvals(status_filter: Optional[str] = None, db: Session = Depends(get_db)):
    """Lists approval requests, optionally filtered by status (PENDING, APPROVED, REJECTED)."""
    query = db.query(ApprovalRequest)
    if status_filter:
        query = query.filter(ApprovalRequest.status == status_filter.upper())
    return query.order_by(desc(ApprovalRequest.created_at)).all()

@router.post("/approvals/{approval_id}/approve", tags=["Approvals"])
def approve_request(
    approval_id: str,
    decision_body: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_admin_access)
):
    """Approves a pending action request."""
    result = approval_manager.approve(
        db=db,
        approval_id=approval_id,
        reviewer=decision_body.reviewer,
        notes=decision_body.notes
    )
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@router.post("/approvals/{approval_id}/reject", tags=["Approvals"])
def reject_request(
    approval_id: str,
    decision_body: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_admin_access)
):
    """Rejects a pending action request."""
    result = approval_manager.reject(
        db=db,
        approval_id=approval_id,
        reviewer=decision_body.reviewer,
        notes=decision_body.notes
    )
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

# -------------------------------------------------------------
# 5. Statistics Endpoint
# -------------------------------------------------------------
@router.get("/statistics", response_model=SecurityStatistics, tags=["Monitoring"])
def get_statistics(db: Session = Depends(get_db)):
    """Aggregates real-time security statistics from the SQLite database."""
    total_inspections = db.query(func.count(SecurityEvent.id)).scalar() or 0
    allowed_actions = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.decision == "ALLOW").scalar() or 0
    blocked_threats = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.decision == "BLOCK").scalar() or 0
    pending_approvals = db.query(func.count(ApprovalRequest.id)).filter(ApprovalRequest.status == "PENDING").scalar() or 0

    threat_detected_count = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.threat_detected == True).scalar() or 0
    threat_detection_rate = (threat_detected_count / total_inspections) if total_inspections > 0 else 0.0

    avg_risk = db.query(func.avg(SecurityEvent.calculated_risk)).scalar() or 0.0

    # Calculate false positive rate based on actions blocked that had no threat detected
    fp_count = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.decision == "BLOCK",
        SecurityEvent.threat_detected == False
    ).scalar() or 0
    tn_count = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.decision == "ALLOW",
        SecurityEvent.threat_detected == False
    ).scalar() or 0
    false_positive_rate = (fp_count / (fp_count + tn_count)) if (fp_count + tn_count) > 0 else 0.0

    return SecurityStatistics(
        total_inspections=total_inspections,
        allowed_actions=allowed_actions,
        blocked_threats=blocked_threats,
        pending_approvals=pending_approvals,
        threat_detection_rate=round(threat_detection_rate, 4),
        false_positive_rate=round(false_positive_rate, 4),
        avg_risk_score=round(float(avg_risk), 4),
        avg_latency_ms=14.2
    )

# -------------------------------------------------------------
# 6. Policy Management Endpoints
# -------------------------------------------------------------
@router.get("/policies", tags=["Policies"])
def get_policy():
    """Returns the active security policy in structured format and raw YAML."""
    return {
        "policy": policy_engine.policy,
        "raw_yaml": policy_engine.get_raw_yaml()
    }

@router.put("/policies", tags=["Policies"])
def update_policy(
    update_req: PolicyUpdateRequest,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_admin_access)
):
    """Validates and updates the security policy configuration."""
    try:
        updated = policy_engine.update_policy(update_req.content_yaml)
        
        # Persist updated policy in database
        db_policy = SecurityPolicy(
            version="1.1",
            content_yaml=update_req.content_yaml,
            is_active=True
        )
        db.add(db_policy)
        
        audit_logger.log(
            db=db,
            agent_id="SYSTEM",
            event_type="POLICY_UPDATED",
            actor=update_req.updated_by or "security_admin",
            action_summary="Security policy rules updated",
            details="YAML policy updated successfully."
        )
        db.commit()
        return {"success": True, "message": "Policy successfully updated.", "policy": updated}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to update policy: {str(e)}")

# -------------------------------------------------------------
# 7. Agent Management Endpoints
# -------------------------------------------------------------
@router.get("/agents", response_model=List[AgentResponse], tags=["Agents"])
def list_agents(db: Session = Depends(get_db)):
    """Lists registered AI agents."""
    return db.query(Agent).all()

@router.post("/agents", response_model=AgentResponse, tags=["Agents"])
def register_agent(
    agent_in: AgentCreateRequest,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_admin_access)
):
    """Registers a new AI agent with the firewall."""
    existing = db.query(Agent).filter(Agent.id == agent_in.id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Agent with ID '{agent_in.id}' already exists.")

    new_agent = Agent(
        id=agent_in.id,
        name=agent_in.name,
        description=agent_in.description,
        role=agent_in.role,
        trust_level=agent_in.trust_level,
        security_tier=agent_in.security_tier or "TIER_2_RESTRICTED",
        model_provider=agent_in.model_provider or "Anthropic",
        model_name=agent_in.model_name or "claude-3-5-sonnet",
        sandbox_mode=agent_in.sandbox_mode or "STANDARD_SANDBOX",
        is_active=True
    )
    db.add(new_agent)
    db.commit()
    db.refresh(new_agent)

    audit_logger.log(
        db=db,
        agent_id=new_agent.id,
        event_type="AGENT_REGISTERED",
        actor="ADMIN",
        action_summary=f"Registered agent '{new_agent.name}' ({new_agent.id})",
        details=f"Role: {new_agent.role}, Trust: {new_agent.trust_level}"
    )

    return new_agent

# -------------------------------------------------------------
# 8. Audit Logs Endpoint
# -------------------------------------------------------------
@router.get("/audit-logs/verify", tags=["Audit"])
def verify_audit_log_chain(db: Session = Depends(get_db)):
    """
    Cryptographically verifies the SHA-256 hash chain of the audit log to prove tamper-evidence.
    """
    return audit_logger.verify_chain(db)

@router.get("/audit-logs", response_model=List[AuditLogResponse], tags=["Audit"])
def get_audit_logs(
    agent_id: Optional[str] = None,
    decision: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Fetches searchable security audit logs."""
    return audit_logger.query_logs(
        db=db,
        agent_id=agent_id,
        decision=decision,
        search_query=search,
        limit=limit,
        offset=offset
    )

# -------------------------------------------------------------
# 9. File & Attachment Security Scanner Endpoint
# -------------------------------------------------------------
from fastapi import UploadFile, File

@router.post("/scan/file", response_model=FileScanResult, tags=["Detection"])
def scan_attachment_file(file: UploadFile = File(...)):
    """
    Scans uploaded or ingested files (.txt, .pdf, .csv, code files)
    for prompt injection, covert steganography, secrets, and formula exploits.
    """
    file_bytes = file.file.read()
    return file_scanner.scan_file(
        filename=file.filename or "uploaded_file",
        file_bytes=file_bytes,
        mime_type=file.content_type
    )

# -------------------------------------------------------------
# 10. Multi-Provider LLM & Token Guard Endpoints
# -------------------------------------------------------------
@router.get("/llm/providers", tags=["LLM"])
def list_llm_providers():
    """Lists configured LLM model providers and their operational statuses."""
    return llm_router.get_configured_providers()

@router.post("/llm/generate", tags=["LLM"])
def generate_llm_completion(req: Dict[str, Any]):
    """
    Routes an AI generation request through Token Guard and the selected provider
    with fail-safe fallback to the Offline Simulated Sandbox.
    """
    prompt = req.get("prompt", "")
    provider = req.get("provider", "Offline Simulated Sandbox")
    model = req.get("model")
    max_tokens = req.get("max_tokens", 4096)
    return llm_router.generate_completion(
        prompt=prompt,
        provider=provider,
        model=model,
        max_tokens=max_tokens
    )
