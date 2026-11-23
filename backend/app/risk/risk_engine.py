from typing import Dict, Any, Tuple
from ..policies.policy_engine import policy_engine

class RiskAssessmentEngine:
    """
    Computes normalized, reproducible risk scores for AI agent tool execution requests.
    Formula: Risk = Action Severity * (1 - Target Trust) * Data Sensitivity
    
    All terms are strictly normalized in range [0.0, 1.0].
    """

    def calculate_risk(
        self,
        action_type: str,
        target_resource: str,
        parameters: Dict[str, Any],
        is_tainted: bool = False,
        threat_detected: bool = False,
        override_severity: float = None,
        override_target_trust: float = None,
        override_data_sensitivity: float = None
    ) -> Dict[str, Any]:
        try:
            # 1. Action Severity (0.0 - 1.0)
            if override_severity is not None:
                action_severity = max(0.0, min(1.0, float(override_severity)))
            else:
                action_severity = policy_engine.get_action_severity(action_type)

            # 2. Target Trust (0.0 - 1.0)
            if override_target_trust is not None:
                target_trust = max(0.0, min(1.0, float(override_target_trust)))
            else:
                target_trust = policy_engine.get_target_trust(target_resource, is_untrusted_source=is_tainted)

            # 3. Data Sensitivity (0.0 - 1.0)
            if override_data_sensitivity is not None:
                data_sensitivity = max(0.0, min(1.0, float(override_data_sensitivity)))
            else:
                data_sensitivity = policy_engine.get_data_sensitivity(target_resource, parameters)

            # Target Risk factor = (1 - Target Trust)
            target_risk_factor = 1.0 - target_trust

            # Base normalized risk formula
            calculated_risk = action_severity * target_risk_factor * data_sensitivity

            # Threat / Taint Escalation Multipliers:
            # If an active prompt injection/hidden instruction was detected,
            # or if untrusted content attempted a sensitive action, escalate risk.
            if threat_detected:
                # Direct attack detected: force risk into high/critical zone
                calculated_risk = max(calculated_risk, 0.85)
            elif is_tainted and action_severity >= 0.70:
                # Tainted source attempting sensitive action (e.g. send_email, delete_file)
                # Elevate risk to at least 0.75 (BLOCK zone)
                calculated_risk = max(calculated_risk, 0.75)

            # Clamp final score strictly between 0.0 and 1.0
            final_risk = round(max(0.0, min(1.0, calculated_risk)), 4)

            # Get policy thresholds
            thresholds = policy_engine.get_thresholds()
            allow_max = thresholds.get("allow_max", 0.30)
            ask_human_max = thresholds.get("ask_human_max", 0.70)

            if final_risk < allow_max:
                risk_tier = "LOW"
                recommended_action = "ALLOW"
            elif final_risk <= ask_human_max:
                risk_tier = "MEDIUM"
                recommended_action = "ASK_HUMAN"
            else:
                risk_tier = "HIGH"
                recommended_action = "BLOCK"

            return {
                "risk_score": final_risk,
                "risk_tier": risk_tier,
                "recommended_action": recommended_action,
                "components": {
                    "action_severity": round(action_severity, 3),
                    "target_trust": round(target_trust, 3),
                    "target_risk_factor": round(target_risk_factor, 3),
                    "data_sensitivity": round(data_sensitivity, 3)
                },
                "breakdown_explanation": (
                    f"Risk Score {final_risk:.2f} [{risk_tier}]: "
                    f"Action Severity ({action_severity:.2f}) x "
                    f"[1 - Target Trust ({target_trust:.2f})] x "
                    f"Data Sensitivity ({data_sensitivity:.2f})"
                    f"{' [Escalated due to detected threat]' if threat_detected else ''}"
                    f"{' [Escalated due to tainted external origin]' if (is_tainted and action_severity >= 0.70) else ''}"
                )
            }
        except Exception as e:
            # Fail closed: return maximum risk 1.0 on calculation error
            return {
                "risk_score": 1.0,
                "risk_tier": "CRITICAL_ERROR",
                "recommended_action": "BLOCK",
                "components": {
                    "action_severity": 1.0,
                    "target_trust": 0.0,
                    "target_risk_factor": 1.0,
                    "data_sensitivity": 1.0
                },
                "breakdown_explanation": f"Fail-Closed: Risk assessment calculation failed ({str(e)}). Assumed maximum risk."
            }

risk_engine = RiskAssessmentEngine()
