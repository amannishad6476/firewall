from typing import Dict, Any, List, Optional
from ..schemas.firewall_schemas import OriginType, ContextTaintInfo

# Origins considered inherently untrusted (sources that can carry indirect prompt injection)
UNTRUSTED_ORIGINS = {
    OriginType.WEBPAGE,
    OriginType.FILE,
    OriginType.EXTERNAL_API,
    OriginType.TOOL_OUTPUT
}

# Operations classified as sensitive
SENSITIVE_ACTIONS = {
    "send_email",
    "delete_file",
    "execute_sql",
    "make_payment",
    "modify_database",
    "execute_command",
    "share_document"
}

class TaintTracker:
    """
    Tracks provenance of instructions and content flowing into the AI agent.
    Enforces the critical security rule: Untrusted external content must never
    independently authorize sensitive actions.
    """

    def analyze_taint(
        self,
        origin: OriginType,
        action_type: str,
        original_user_goal: str,
        external_instruction: Optional[str] = None,
        threat_detected: bool = False
    ) -> Dict[str, Any]:
        """
        Determines taint status and whether an action violates provenance trust boundaries.
        """
        # Determine if source is tainted
        is_origin_untrusted = origin in UNTRUSTED_ORIGINS
        is_tainted = is_origin_untrusted or threat_detected or bool(external_instruction)
        
        is_sensitive_action = action_type.lower() in SENSITIVE_ACTIONS
        
        # Check alignment between user goal and requested action
        user_authorized = self._is_user_authorized(action_type, original_user_goal)
        
        # Provenance violation check:
        # If the origin is tainted/untrusted AND the action is sensitive AND not explicitly authorized by the user,
        # it is an indirect taint escalation attack.
        taint_violation = False
        violation_reason = None
        
        if is_tainted and is_sensitive_action and not user_authorized:
            taint_violation = True
            violation_reason = (
                f"Taint Provenance Violation: Sensitive action '{action_type}' was triggered by untrusted "
                f"external source [{origin.value}]. Original user goal '{original_user_goal}' did not authorize this action."
            )
        elif is_tainted and threat_detected and is_sensitive_action:
            taint_violation = True
            violation_reason = (
                f"Taint Provenance Block: Threat detected in untrusted content while attempting sensitive action '{action_type}'."
            )

        return {
            "is_tainted": is_tainted,
            "origin": origin.value,
            "is_sensitive_action": is_sensitive_action,
            "user_authorized": user_authorized,
            "taint_violation": taint_violation,
            "violation_reason": violation_reason,
            "original_user_goal": original_user_goal,
            "external_instruction": external_instruction
        }

    def _is_user_authorized(self, action_type: str, user_goal: str) -> bool:
        """
        Heuristic to verify if the original user goal explicitly authorized
        the requested sensitive action.
        """
        if not user_goal:
            return False
            
        goal_lower = user_goal.lower()
        
        if action_type == "send_email":
            return any(k in goal_lower for k in ["send email", "email", "mail to", "forward to"])
        elif action_type == "delete_file":
            return any(k in goal_lower for k in ["delete file", "remove file", "clean up file", "delete"])
        elif action_type == "execute_sql":
            return any(k in goal_lower for k in ["run query", "execute sql", "query database", "update database"])
        elif action_type == "make_payment":
            return any(k in goal_lower for k in ["pay", "payment", "transfer money", "checkout"])
        elif action_type in ["read_webpage", "read_file", "search_docs"]:
            # Informational actions are standard read behaviors
            return True
            
        return False

taint_tracker = TaintTracker()
