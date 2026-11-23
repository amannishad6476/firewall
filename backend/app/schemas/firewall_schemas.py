from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum

class OriginType(str, Enum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    WEBPAGE = "WEBPAGE"
    FILE = "FILE"
    EXTERNAL_API = "EXTERNAL_API"
    TOOL_OUTPUT = "TOOL_OUTPUT"

class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    ASK_HUMAN = "ASK_HUMAN"
    BLOCK = "BLOCK"

class ThreatCategory(str, Enum):
    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    HIDDEN_INSTRUCTION = "HIDDEN_INSTRUCTION"
    ZERO_WIDTH_ATTACK = "ZERO_WIDTH_ATTACK"
    BASE64_OBFUSCATION = "BASE64_OBFUSCATION"
    SENSITIVE_DATA_LEAK = "SENSITIVE_DATA_LEAK"
    UNAUTHORIZED_COMMAND = "UNAUTHORIZED_COMMAND"
    POLICY_VIOLATION = "POLICY_VIOLATION"

class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class InputScanRequest(BaseModel):
    content: str
    source_type: OriginType = OriginType.WEBPAGE
    strict_mode: bool = False

class InputScanResult(BaseModel):
    detected: bool
    threat_category: ThreatCategory = ThreatCategory.NONE
    severity: ThreatSeverity = ThreatSeverity.LOW
    evidence: List[str] = Field(default_factory=list)
    explanation: str = "No suspicious instructions detected"
    raw_findings: Dict[str, Any] = Field(default_factory=dict)

class ContextTaintInfo(BaseModel):
    source: OriginType = OriginType.USER
    is_tainted: bool = False
    original_user_goal: str = "Perform general assistance"
    external_instruction: Optional[str] = None

class FirewallCheckRequest(BaseModel):
    agent_id: str = "default_agent"
    session_id: Optional[str] = None
    action_type: str  # read_webpage, read_file, send_email, delete_file, execute_sql
    target_resource: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    context_taint: ContextTaintInfo = Field(default_factory=ContextTaintInfo)
    content_to_scan: Optional[str] = None

class FirewallCheckResponse(BaseModel):
    event_id: str
    decision: DecisionType
    risk_score: float
    action_severity: float
    target_trust: float
    data_sensitivity: float
    threat_detected: bool
    threat_category: Optional[str] = None
    threat_severity: Optional[str] = None
    reason: str
    approval_required: bool
    approval_id: Optional[str] = None

class FirewallExecuteRequest(BaseModel):
    event_id: Optional[str] = None
    approval_id: Optional[str] = None
    agent_id: str = "default_agent"
    action_type: str
    target_resource: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    context_taint: ContextTaintInfo = Field(default_factory=ContextTaintInfo)
    content_to_scan: Optional[str] = None

class FirewallExecuteResponse(BaseModel):
    success: bool
    event_id: str
    decision: DecisionType
    execution_status: str  # EXECUTED, BLOCKED, REJECTED, PENDING_APPROVAL
    result: Optional[Any] = None
    message: str

class ApprovalDecisionRequest(BaseModel):
    reviewer: str = "security_officer"
    notes: Optional[str] = None

class ApprovalResponse(BaseModel):
    id: str
    event_id: str
    agent_id: str
    action_type: str
    target_resource: str
    parameters: Optional[str] = None
    calculated_risk: float
    threat_category: Optional[str] = None
    reason: str
    status: str
    created_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class SecurityEventResponse(BaseModel):
    id: str
    timestamp: datetime
    agent_id: str
    session_id: Optional[str] = None
    action_type: str
    target_resource: str
    parameters: Optional[str] = None
    threat_detected: bool
    threat_category: Optional[str] = None
    threat_severity: Optional[str] = None
    threat_details: Optional[str] = None
    taint_source: Optional[str] = None
    is_tainted: bool
    action_severity: float
    target_trust: float
    data_sensitivity: float
    calculated_risk: float
    decision: str
    decision_reason: str
    execution_status: str
    execution_result: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class AuditLogResponse(BaseModel):
    id: str
    timestamp: datetime
    event_id: Optional[str] = None
    agent_id: str
    event_type: str
    actor: str
    action_summary: str
    decision: Optional[str] = None
    risk_score: Optional[float] = None
    details: Optional[str] = None
    ip_address: str

    model_config = ConfigDict(from_attributes=True)

class AgentCreateRequest(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    role: str = "assistant"
    trust_level: float = 0.5

class AgentResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    role: str
    trust_level: float
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class PolicyUpdateRequest(BaseModel):
    content_yaml: str
    updated_by: Optional[str] = "security_admin"

class SecurityStatistics(BaseModel):
    total_inspections: int
    allowed_actions: int
    blocked_threats: int
    pending_approvals: int
    threat_detection_rate: float
    false_positive_rate: float
    avg_risk_score: float
    avg_latency_ms: float
