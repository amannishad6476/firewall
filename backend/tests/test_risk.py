import pytest
from backend.app.risk.risk_engine import risk_engine

def test_risk_formula_bounds():
    # Test formula: Risk = Action Severity * (1 - Target Trust) * Data Sensitivity
    # Case: read_webpage (0.2), trusted internal target (0.9), public data (0.1)
    res = risk_engine.calculate_risk(
        action_type="read_webpage",
        target_resource="https://internal.corp",
        parameters={},
        is_tainted=False,
        override_severity=0.2,
        override_target_trust=0.9,
        override_data_sensitivity=0.1
    )
    # Expected: 0.2 * (1 - 0.9) * 0.1 = 0.2 * 0.1 * 0.1 = 0.002
    assert 0.0 <= res["risk_score"] <= 1.0
    assert res["risk_score"] < 0.30
    assert res["recommended_action"] == "ALLOW"

def test_risk_formula_high_severity():
    # Case: delete_file (0.9), untrusted target (0.1), confidential data (0.8)
    res = risk_engine.calculate_risk(
        action_type="delete_file",
        target_resource="confidential.db",
        parameters={},
        is_tainted=False,
        override_severity=0.9,
        override_target_trust=0.1,
        override_data_sensitivity=0.8
    )
    # 0.9 * 0.9 * 0.8 = 0.648 (in ASK_HUMAN or elevated zone)
    assert 0.0 <= res["risk_score"] <= 1.0
    assert res["risk_tier"] in ["MEDIUM", "HIGH"]

def test_risk_threat_detected_escalation():
    # Direct attack detected should force risk to at least 0.85
    res = risk_engine.calculate_risk(
        action_type="read_webpage",
        target_resource="https://news.corp",
        parameters={},
        is_tainted=False,
        threat_detected=True
    )
    assert res["risk_score"] >= 0.85
    assert res["recommended_action"] == "BLOCK"

def test_risk_fail_closed_on_error():
    # Passing invalid non-numeric parameters that could crash calculation
    res = risk_engine.calculate_risk(
        action_type="read_webpage",
        target_resource="target",
        parameters={},
        override_severity="invalid_type"
    )
    assert res["risk_score"] == 1.0
    assert res["recommended_action"] == "BLOCK"
    assert "Fail-Closed" in res["breakdown_explanation"]
