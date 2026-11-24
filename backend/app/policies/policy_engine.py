import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from ..config.settings import settings

class PolicyEngine:
    """
    Loads, caches, and evaluates YAML-based security policies for the firewall.
    Enforces mandatory rules, domain restrictions, action severities, and agent role permissions.
    """

    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = Path(policy_path or settings.POLICY_FILE_PATH)
        self.policy: Dict[str, Any] = {}
        self.load_policy()

    def load_policy(self) -> Dict[str, Any]:
        """Loads and parses the YAML security policy."""
        if not self.policy_path.exists():
            # Fallback default policy
            self.policy = self._get_fallback_policy()
            return self.policy
        
        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                self.policy = yaml.safe_load(f) or self._get_fallback_policy()
        except Exception:
            self.policy = self._get_fallback_policy()
            
        return self.policy

    def update_policy(self, content_yaml: str) -> Dict[str, Any]:
        """Validates and updates the active policy from YAML content string."""
        parsed = yaml.safe_load(content_yaml)
        if not isinstance(parsed, dict):
            raise ValueError("Invalid YAML policy structure: expected dictionary at root")
        
        # Validate required keys
        required_keys = ["thresholds", "sensitive_operations", "action_severities"]
        for key in required_keys:
            if key not in parsed:
                raise ValueError(f"Missing required policy section: '{key}'")
        
        # Save to disk
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.policy_path, "w", encoding="utf-8") as f:
            f.write(content_yaml)
            
        self.policy = parsed
        return self.policy

    def get_raw_yaml(self) -> str:
        """Returns the current policy as raw YAML string."""
        if self.policy_path.exists():
            with open(self.policy_path, "r", encoding="utf-8") as f:
                return f.read()
        return yaml.dump(self.policy)

    def is_domain_blocked(self, target: str) -> bool:
        """Checks if target domain is explicitly in blocked domains list."""
        blocked = self.policy.get("domains", {}).get("blocked", [])
        lowered = target.lower()
        return any(b.lower() in lowered for b in blocked)

    def is_domain_allowed(self, target: str) -> bool:
        """Checks if target domain is explicitly in allowed domains list."""
        allowed = self.policy.get("domains", {}).get("allowed", [])
        lowered = target.lower()
        return any(a.lower() in lowered for a in allowed)

    def get_action_severity(self, action_type: str) -> float:
        """Returns normalized severity score for action (0.0 - 1.0)."""
        severities = self.policy.get("action_severities", {})
        return float(severities.get(action_type, 0.5))

    def get_target_trust(self, target: str, is_untrusted_source: bool = False) -> float:
        """Determines normalized trust level for target resource (0.0 - 1.0)."""
        trust_ratings = self.policy.get("target_trust_ratings", {})
        
        if self.is_domain_blocked(target):
            return 0.0
            
        if self.is_domain_allowed(target):
            return 0.95
            
        if is_untrusted_source:
            return float(trust_ratings.get("external_web", 0.15))
            
        if any(target.endswith(ext) for ext in [".confidential", ".env", ".key", ".pem", "shadow"]):
            return 0.05
            
        return 0.50

    def get_data_sensitivity(self, target: str, parameters: Dict[str, Any]) -> float:
        """Determines normalized data sensitivity (0.0 - 1.0)."""
        sensitivities = self.policy.get("data_sensitivities", {})
        
        target_lower = target.lower()
        param_str = str(parameters).lower()
        
        # Check for credential or secret markers
        if any(k in target_lower or k in param_str for k in ["password", "secret", "private_key", ".env", "api_key", "token"]):
            return float(sensitivities.get("credentials", 1.0))
            
        if any(k in target_lower or k in param_str for k in ["confidential", "salary", "ssn", "financial", "credit_card"]):
            return float(sensitivities.get("confidential", 0.8))
            
        if any(k in target_lower or k in param_str for k in ["customer", "employee", "email"]):
            return float(sensitivities.get("pii", 0.7))
            
        return float(sensitivities.get("internal", 0.4))

    def get_thresholds(self) -> Dict[str, float]:
        """Returns decision risk thresholds."""
        return self.policy.get("thresholds", {
            "allow_max": 0.30,
            "ask_human_max": 0.70,
            "block_min": 0.70
        })

    def check_agent_permissions(self, agent_id: str, action_type: str) -> Dict[str, Any]:
        """Validates agent permissions according to policy."""
        agent_perms = self.policy.get("agent_permissions", {}).get(agent_id)
        if not agent_perms:
            # Fallback to default_agent permissions
            agent_perms = self.policy.get("agent_permissions", {}).get("default_agent", {})

        prohibited = agent_perms.get("prohibited_tools", [])
        if action_type in prohibited:
            return {
                "allowed": False,
                "reason": f"Tool '{action_type}' is strictly prohibited for agent '{agent_id}' under current policy."
            }

        requires_approval = action_type in agent_perms.get("requires_approval_tools", [])
        allowed_tools = agent_perms.get("allowed_tools", [])

        # Zero-trust policy: tool must be recognized in allowed_tools or requires_approval_tools
        if allowed_tools and (action_type not in allowed_tools) and not requires_approval:
            return {
                "allowed": False,
                "reason": f"Tool '{action_type}' is unlisted/unauthorized for agent '{agent_id}' under zero-trust policy."
            }

        return {
            "allowed": True,
            "requires_approval": requires_approval,
            "reason": "Permitted under role policy"
        }

    def _get_fallback_policy(self) -> Dict[str, Any]:
        return {
            "thresholds": {"allow_max": 0.30, "ask_human_max": 0.70, "block_min": 0.70},
            "sensitive_operations": ["send_email", "delete_file", "execute_sql"],
            "action_severities": {"read_webpage": 0.2, "read_file": 0.3, "send_email": 0.75, "delete_file": 0.9, "execute_sql": 0.85},
            "target_trust_ratings": {"external_web": 0.15, "user_input": 0.8},
            "data_sensitivities": {"public": 0.1, "internal": 0.4, "confidential": 0.8, "credentials": 1.0},
            "domains": {"allowed": ["api.internal.corp"], "blocked": ["attacker.com"]}
        }

policy_engine = PolicyEngine()
