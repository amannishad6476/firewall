from typing import Dict, Any, List
from sqlalchemy.orm import Session
from ..schemas.firewall_schemas import FirewallCheckRequest, OriginType, ContextTaintInfo, DecisionType
from ..firewall.engine import firewall_engine
from .protected_tools import protected_tools

class MCPFirewallAdapter:
    """
    Model Context Protocol (MCP) compatible server adapter.
    Exposes protected tools conforming to MCP specifications and ensures all tool calls
    pass through the AI Agent Firewall before execution.
    """

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns MCP-compliant tool declarations."""
        return [
            {
                "name": "read_webpage",
                "description": "Fetches and reads content from a remote webpage or internal URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "The URL of the webpage to read."}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "read_file",
                "description": "Reads contents of a specified file within the sandbox environment.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string", "description": "The relative filename in sandbox."}
                    },
                    "required": ["filename"]
                }
            },
            {
                "name": "send_email",
                "description": "Sends an email message to a specified recipient.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string", "description": "The email address of the recipient."},
                        "subject": {"type": "string", "description": "The subject line of the email."},
                        "body": {"type": "string", "description": "The body content of the email."}
                    },
                    "required": ["recipient", "body"]
                }
            },
            {
                "name": "delete_file",
                "description": "Deletes a specified file within the sandbox directory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string", "description": "The filename to remove from sandbox."}
                    },
                    "required": ["filename"]
                }
            },
            {
                "name": "execute_sql",
                "description": "Executes a query against the authorized database.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "database": {"type": "string", "description": "Database identifier."},
                        "query": {"type": "string", "description": "SQL statement to run."}
                    },
                    "required": ["database", "query"]
                }
            }
        ]

    def handle_mcp_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        agent_id: str,
        db: Session,
        context_taint: ContextTaintInfo,
        content_to_scan: str = None
    ) -> Dict[str, Any]:
        """
        Intercepts an MCP 'tools/call' request, validates it through the AI Firewall,
        and only executes if allowed or approved.
        """
        target_resource = arguments.get("url") or arguments.get("filename") or arguments.get("recipient") or arguments.get("database") or "system"

        # Construct firewall check
        check_req = FirewallCheckRequest(
            agent_id=agent_id,
            action_type=tool_name,
            target_resource=str(target_resource),
            parameters=arguments,
            context_taint=context_taint,
            content_to_scan=content_to_scan
        )

        # Inspect through firewall
        firewall_res = firewall_engine.inspect_and_evaluate(check_req, db)

        if firewall_res.decision == DecisionType.BLOCK:
            return {
                "isError": True,
                "content": [{
                    "type": "text",
                    "text": f"FIREWALL_BLOCKED: {firewall_res.reason} (Risk: {firewall_res.risk_score:.2f})"
                }],
                "firewall_metadata": {
                    "event_id": firewall_res.event_id,
                    "decision": firewall_res.decision.value,
                    "risk_score": firewall_res.risk_score
                }
            }

        if firewall_res.decision == DecisionType.ASK_HUMAN:
            return {
                "isError": True,
                "content": [{
                    "type": "text",
                    "text": f"FIREWALL_APPROVAL_REQUIRED: Action paused. Approval Request ID: {firewall_res.approval_id}. Reason: {firewall_res.reason}"
                }],
                "firewall_metadata": {
                    "event_id": firewall_res.event_id,
                    "decision": firewall_res.decision.value,
                    "approval_id": firewall_res.approval_id,
                    "risk_score": firewall_res.risk_score
                }
            }

        # Decision is ALLOW: execute sandboxed tool
        exec_res = protected_tools.execute_tool(tool_name, str(target_resource), arguments)
        return {
            "isError": not exec_res.get("success", False),
            "content": [{
                "type": "text",
                "text": str(exec_res)
            }],
            "firewall_metadata": {
                "event_id": firewall_res.event_id,
                "decision": firewall_res.decision.value,
                "risk_score": firewall_res.risk_score
            }
        }

mcp_adapter = MCPFirewallAdapter()
