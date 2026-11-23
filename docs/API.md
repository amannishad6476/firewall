# AI Agent Firewall REST API Reference

The AI Agent Firewall provides a RESTful interface for inspecting, executing, monitoring, and managing agent security policies.

Base URL: `http://127.0.0.1:8000/api/v1`

---

## 1. System Health
### `GET /health`
Returns system health, database status, and fail-closed posture.
**Response**:
```json
{
  "status": "healthy",
  "service": "AI Agent Firewall & Security Platform",
  "version": "1.0.0",
  "database": "connected",
  "fail_closed_mode": true
}
```

---

## 2. Firewall Evaluation & Execution

### `POST /api/v1/firewall/check`
Inspects an agent's intended tool call without executing it. Returns normalized risk score, detected threats, and decision.

**Request Body**:
```json
{
  "agent_id": "default_agent",
  "action_type": "read_webpage",
  "target_resource": "https://external.corp/page",
  "parameters": {},
  "context_taint": {
    "source": "USER",
    "is_tainted": false,
    "original_user_goal": "Summarize research"
  },
  "content_to_scan": "Optional text to scan for injection"
}
```

**Response (ALLOW)**:
```json
{
  "event_id": "710657e0-abe3-4680-8c1f-fe125ad763b6",
  "decision": "ALLOW",
  "risk_score": 0.04,
  "action_severity": 0.20,
  "target_trust": 0.80,
  "data_sensitivity": 0.25,
  "threat_detected": false,
  "threat_category": null,
  "threat_severity": null,
  "reason": "Operation is within safe policy thresholds.",
  "approval_required": false,
  "approval_id": null
}
```

### `POST /api/v1/firewall/execute`
Executes a protected tool action *only* if authorized by the firewall or authorized via prior human approval. Direct bypass is prohibited.

**Request Body**:
```json
{
  "approval_id": null,
  "agent_id": "default_agent",
  "action_type": "read_file",
  "target_resource": "company_overview.txt",
  "parameters": {},
  "context_taint": {
    "source": "USER",
    "is_tainted": false,
    "original_user_goal": "Read company overview"
  }
}
```

**Response**:
```json
{
  "success": true,
  "event_id": "9b12a3c4-...",
  "decision": "ALLOW",
  "execution_status": "EXECUTED",
  "result": {
    "success": true,
    "filename": "company_overview.txt",
    "size_bytes": 86,
    "content": "Company Overview: ..."
  },
  "message": "Action authorized by firewall and safely executed."
}
```

---

## 3. Human Approval Workflow

### `GET /api/v1/approvals`
Lists pending or resolved approval requests. Filterable by `?status_filter=PENDING`.

### `POST /api/v1/approvals/{id}/approve`
Approves a pending action.
**Request Body**:
```json
{
  "reviewer": "security_officer",
  "notes": "Verified business requirement"
}
```

### `POST /api/v1/approvals/{id}/reject`
Rejects a pending action.
**Request Body**:
```json
{
  "reviewer": "security_officer",
  "notes": "Suspicious exfiltration recipient"
}
```

---

## 4. Monitoring & Telemetry

### `GET /api/v1/statistics`
Returns real-time aggregated metrics directly from SQLite:
```json
{
  "total_inspections": 32,
  "allowed_actions": 6,
  "blocked_threats": 23,
  "pending_approvals": 3,
  "threat_detection_rate": 0.7188,
  "false_positive_rate": 0.0,
  "avg_risk_score": 0.684,
  "avg_latency_ms": 14.2
}
```

### `GET /api/v1/events`
Returns paginated security events history.
Query parameters: `agent_id`, `decision`, `threat_only`, `limit`, `offset`.

### `GET /api/v1/audit-logs`
Returns searchable audit trail logs.
Query parameters: `agent_id`, `decision`, `search`, `limit`, `offset`.

---

## 5. Security Policies & Agents

### `GET /api/v1/policies`
Returns the active declarative security policy in structured JSON and raw YAML.

### `PUT /api/v1/policies`
Updates the active YAML policy configuration after schema validation.

### `GET /api/v1/agents`
Lists registered agents, roles, and trust ratings.

### `POST /api/v1/agents`
Registers a new AI agent with role-based tool restrictions.
