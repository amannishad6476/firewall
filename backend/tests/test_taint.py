import pytest
from backend.app.context.taint_tracker import taint_tracker
from backend.app.schemas.firewall_schemas import OriginType

def test_untrusted_origin_taints_context():
    res = taint_tracker.analyze_taint(
        origin=OriginType.WEBPAGE,
        action_type="read_webpage",
        original_user_goal="Research AI trends"
    )
    assert res["is_tainted"] is True
    assert res["taint_violation"] is False  # Read action is non-sensitive

def test_untrusted_origin_sensitive_action_causes_violation():
    # Untrusted webpage tries to trigger send_email without user authorization
    res = taint_tracker.analyze_taint(
        origin=OriginType.WEBPAGE,
        action_type="send_email",
        original_user_goal="Read webpage and summarize"
    )
    assert res["is_tainted"] is True
    assert res["is_sensitive_action"] is True
    assert res["user_authorized"] is False
    assert res["taint_violation"] is True
    assert "Taint Provenance Violation" in res["violation_reason"]

def test_user_authorized_sensitive_action_is_allowed():
    # User explicitly requested email dispatch
    res = taint_tracker.analyze_taint(
        origin=OriginType.USER,
        action_type="send_email",
        original_user_goal="Send email to team with weekly update"
    )
    assert res["is_sensitive_action"] is True
    assert res["user_authorized"] is True
    assert res["taint_violation"] is False

def test_tainted_file_deletion_is_blocked():
    res = taint_tracker.analyze_taint(
        origin=OriginType.EXTERNAL_API,
        action_type="delete_file",
        original_user_goal="Check weather update"
    )
    assert res["taint_violation"] is True

def test_trusted_system_prompt_origin():
    res = taint_tracker.analyze_taint(
        origin=OriginType.SYSTEM,
        action_type="read_file",
        original_user_goal="Initialize system prompt"
    )
    assert res["is_tainted"] is False
    assert res["taint_violation"] is False
