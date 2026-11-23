import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from ..schemas.firewall_schemas import (
    FirewallCheckRequest,
    FirewallCheckResponse,
    DecisionType,
    ThreatCategory,
    ThreatSeverity,
    OriginType
)
from ..models.db_models import SecurityEvent, Agent
from ..detection.input_scanner import scanner
from ..context.taint_tracker import taint_tracker
from ..policies.policy_engine import policy_engine
from ..risk.risk_engine import risk_engine
from ..approvals.manager import approval_manager
from ..logging.audit_logger import audit_logger

class FirewallEngine:
    """
    Central security middleware engine inspecting all agent tool execution requests.
    Enforces fail-closed zero-trust validation through input scanning, taint provenance tracking,
    policy rule checks, and normalized risk calculation.
    """

    def inspect_and_evaluate(self, request: FirewallCheckRequest, db: Session) -> FirewallCheckResponse:
        try:
            # 1. Agent Validation
            agent = db.query(Agent).filter(Agent.id == request.agent_id).first()
            if not agent or not agent.is_active:
                return self._build_fail_closed_response(
                    request=request,
                    reason=f"Agent '{request.agent_id}' is invalid, disabled, or not registered."
                )

            # Check agent tool permissions in policy
            perm_check = policy_engine.check_agent_permissions(request.agent_id, request.action_type)
            if not perm_check["allowed"]:
                return self._record_and_return_block(
                    db=db,
                    request=request,
                    threat_cat=ThreatCategory.POLICY_VIOLATION,
                    severity=ThreatSeverity.HIGH,
                    reason=perm_check["reason"],
                    risk=0.85
                )

            # 2. Blocked Domains / Target verification
            if policy_engine.is_domain_blocked(request.target_resource):
                return self._record_and_return_block(
                    db=db,
                    request=request,
                    threat_cat=ThreatCategory.POLICY_VIOLATION,
                    severity=ThreatSeverity.CRITICAL,
                    reason=f"Target resource '{request.target_resource}' is on the domain blacklist.",
                    risk=0.95
                )

            # 3. Input Scanning (Content to scan or parameters)
            content_to_scan = request.content_to_scan or ""
            if not content_to_scan and request.parameters:
                # Check parameters if content was not explicitly supplied
                param_parts = [str(v) for v in request.parameters.values() if isinstance(v, (str, bytes))]
                content_to_scan = "\n".join(param_parts)

            scan_res = scanner.scan(
                content=content_to_scan,
                source_type=request.context_taint.source
            )

            # 4. Context & Taint Provenance Analysis
            taint_res = taint_tracker.analyze_taint(
                origin=request.context_taint.source,
                action_type=request.action_type,
                original_user_goal=request.context_taint.original_user_goal,
                external_instruction=request.context_taint.external_instruction,
                threat_detected=scan_res.detected
            )

            # 5. Risk Assessment Calculation
            risk_calc = risk_engine.calculate_risk(
                action_type=request.action_type,
                target_resource=request.target_resource,
                parameters=request.parameters,
                is_tainted=taint_res["is_tainted"],
                threat_detected=scan_res.detected
            )
            
            calculated_risk = risk_calc["risk_score"]
            components = risk_calc["components"]

            # 6. Decision Logic
            decision = DecisionType.ALLOW
            reason = "Operation is within safe policy thresholds."
            approval_id = None
            requires_approval = False

            # Rule A: Provenance taint violation (untrusted content commanding sensitive action)
            if taint_res["taint_violation"]:
                decision = DecisionType.BLOCK
                reason = taint_res["violation_reason"]
                calculated_risk = max(calculated_risk, 0.90)

            # Rule B: Explicit threat detected (Prompt injection / hidden instructions)
            elif scan_res.detected:
                decision = DecisionType.BLOCK
                reason = f"Execution blocked due to security threat: {scan_res.explanation}"
                calculated_risk = max(calculated_risk, 0.85)

            # Rule C: Policy-mandated human approval (e.g. for specific tools or roles)
            elif perm_check.get("requires_approval", False) and calculated_risk < 0.70:
                decision = DecisionType.ASK_HUMAN
                requires_approval = True
                reason = f"Policy requires human approval for tool '{request.action_type}' by agent '{request.agent_id}'."

            # Rule D: Risk-based decision thresholds
            elif calculated_risk >= 0.70:
                decision = DecisionType.BLOCK
                reason = f"High calculated risk ({calculated_risk:.2f} >= 0.70). Action blocked."
            elif calculated_risk >= 0.30:
                decision = DecisionType.ASK_HUMAN
                requires_approval = True
                reason = f"Moderate calculated risk ({calculated_risk:.2f} in [0.30, 0.70]). Human approval required."

            # 7. Persist Security Event
            params_json = json.dumps(request.parameters) if request.parameters else "{}"
            threat_details = json.dumps({
                "scan_evidence": scan_res.evidence,
                "taint_analysis": taint_res,
                "risk_breakdown": risk_calc["breakdown_explanation"]
            })

            event = SecurityEvent(
                agent_id=request.agent_id,
                session_id=request.session_id,
                action_type=request.action_type,
                target_resource=request.target_resource,
                parameters=params_json,
                threat_detected=scan_res.detected or taint_res["taint_violation"],
                threat_category=scan_res.threat_category.value if scan_res.detected else (
                    ThreatCategory.UNAUTHORIZED_COMMAND.value if taint_res["taint_violation"] else None
                ),
                threat_severity=scan_res.severity.value if scan_res.detected else (
                    ThreatSeverity.HIGH.value if taint_res["taint_violation"] else None
                ),
                threat_details=threat_details,
                taint_source=request.context_taint.source.value,
                is_tainted=taint_res["is_tainted"],
                action_severity=components["action_severity"],
                target_trust=components["target_trust"],
                data_sensitivity=components["data_sensitivity"],
                calculated_risk=calculated_risk,
                decision=decision.value,
                decision_reason=reason,
                execution_status="BLOCKED" if decision == DecisionType.BLOCK else (
                    "PENDING_APPROVAL" if decision == DecisionType.ASK_HUMAN else "PENDING_EXECUTION"
                )
            )
            db.add(event)
            db.commit()
            db.refresh(event)

            # 8. Human Approval Workflow Creation
            if decision == DecisionType.ASK_HUMAN:
                approval = approval_manager.create_approval_request(
                    db=db,
                    event_id=event.id,
                    agent_id=request.agent_id,
                    action_type=request.action_type,
                    target_resource=request.target_resource,
                    parameters_str=params_json,
                    calculated_risk=calculated_risk,
                    threat_category=event.threat_category,
                    reason=reason
                )
                approval_id = approval.id

            # 9. Audit Logging
            audit_logger.log(
                db=db,
                event_id=event.id,
                agent_id=request.agent_id,
                event_type=f"FIREWALL_DECISION_{decision.value}",
                actor="FIREWALL",
                action_summary=f"Inspected '{request.action_type}' on '{request.target_resource}' -> {decision.value}",
                decision=decision.value,
                risk_score=calculated_risk,
                details=reason
            )

            return FirewallCheckResponse(
                event_id=event.id,
                decision=decision,
                risk_score=calculated_risk,
                action_severity=components["action_severity"],
                target_trust=components["target_trust"],
                data_sensitivity=components["data_sensitivity"],
                threat_detected=event.threat_detected,
                threat_category=event.threat_category,
                threat_severity=event.threat_severity,
                reason=reason,
                approval_required=requires_approval,
                approval_id=approval_id
            )

        except Exception as e:
            # Fail closed: reject on error
            return self._build_fail_closed_response(
                request=request,
                reason=f"Fail-Closed: Firewall processing encountered an internal error: {str(e)}"
            )

    def _build_fail_closed_response(self, request: FirewallCheckRequest, reason: str) -> FirewallCheckResponse:
        return FirewallCheckResponse(
            event_id="error-fail-closed",
            decision=DecisionType.BLOCK,
            risk_score=1.0,
            action_severity=1.0,
            target_trust=0.0,
            data_sensitivity=1.0,
            threat_detected=True,
            threat_category=ThreatCategory.POLICY_VIOLATION.value,
            threat_severity=ThreatSeverity.CRITICAL.value,
            reason=f"Fail-Closed Security Triggered: {reason}",
            approval_required=False,
            approval_id=None
        )

    def _record_and_return_block(
        self,
        db: Session,
        request: FirewallCheckRequest,
        threat_cat: ThreatCategory,
        severity: ThreatSeverity,
        reason: str,
        risk: float
    ) -> FirewallCheckResponse:
        event = SecurityEvent(
            agent_id=request.agent_id,
            session_id=request.session_id,
            action_type=request.action_type,
            target_resource=request.target_resource,
            parameters=json.dumps(request.parameters) if request.parameters else "{}",
            threat_detected=True,
            threat_category=threat_cat.value,
            threat_severity=severity.value,
            threat_details=reason,
            taint_source=request.context_taint.source.value,
            is_tainted=True,
            action_severity=0.8,
            target_trust=0.0,
            data_sensitivity=0.8,
            calculated_risk=risk,
            decision=DecisionType.BLOCK.value,
            decision_reason=reason,
            execution_status="BLOCKED"
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        audit_logger.log(
            db=db,
            event_id=event.id,
            agent_id=request.agent_id,
            event_type="FIREWALL_DECISION_BLOCK",
            actor="FIREWALL",
            action_summary=f"Blocked '{request.action_type}' on '{request.target_resource}'",
            decision="BLOCK",
            risk_score=risk,
            details=reason
        )

        return FirewallCheckResponse(
            event_id=event.id,
            decision=DecisionType.BLOCK,
            risk_score=risk,
            action_severity=0.8,
            target_trust=0.0,
            data_sensitivity=0.8,
            threat_detected=True,
            threat_category=threat_cat.value,
            threat_severity=severity.value,
            reason=reason,
            approval_required=False,
            approval_id=None
        )

firewall_engine = FirewallEngine()
