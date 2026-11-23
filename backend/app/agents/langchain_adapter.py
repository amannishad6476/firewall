from typing import Any, Callable, Dict, Optional
from sqlalchemy.orm import Session
from ..schemas.firewall_schemas import FirewallCheckRequest, OriginType, ContextTaintInfo, DecisionType
from ..firewall.engine import firewall_engine

class LangChainFirewallToolWrapper:
    """
    Adapter enabling seamless integration with LangChain BaseTool instances.
    Intercepts the tool's `_run` or `run` execution and validates via the AI Firewall.
    """

    def __init__(self, tool_name: str, target_param_name: str, func: Callable, agent_id: str = "default_agent"):
        self.name = tool_name
        self.target_param_name = target_param_name
        self.func = func
        self.agent_id = agent_id

    def run(
        self,
        db: Session,
        context_taint: Optional[ContextTaintInfo] = None,
        content_to_scan: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Executes the wrapped tool only if authorized by the AI Firewall.
        """
        target = str(kwargs.get(self.target_param_name, "general_target"))
        taint_info = context_taint or ContextTaintInfo(source=OriginType.USER, is_tainted=False)

        check_request = FirewallCheckRequest(
            agent_id=self.agent_id,
            action_type=self.name,
            target_resource=target,
            parameters=kwargs,
            context_taint=taint_info,
            content_to_scan=content_to_scan
        )

        decision = firewall_engine.inspect_and_evaluate(check_request, db)

        if decision.decision == DecisionType.BLOCK:
            return {
                "blocked": True,
                "error": f"Tool execution blocked by AI Firewall: {decision.reason}",
                "risk_score": decision.risk_score,
                "event_id": decision.event_id
            }

        if decision.decision == DecisionType.ASK_HUMAN:
            return {
                "approval_required": True,
                "approval_id": decision.approval_id,
                "message": f"Action paused. Awaiting human approval: {decision.reason}",
                "risk_score": decision.risk_score,
                "event_id": decision.event_id
            }

        # Execute underlying tool function
        result = self.func(**kwargs)
        return {
            "blocked": False,
            "result": result,
            "risk_score": decision.risk_score,
            "event_id": decision.event_id
        }
