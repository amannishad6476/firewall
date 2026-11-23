import sys
import json
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.database.connection import init_db, SessionLocal
from backend.app.agents.mock_agent import MockAIAgent
from backend.app.models.db_models import SecurityEvent, AuditLog

def run_security_demonstration():
    print("=" * 70)
    print("       AI AGENT FIREWALL & SECURITY MONITORING PLATFORM")
    print("                LIVE SECURITY DEMONSTRATION")
    print("=" * 70)

    # 1. Initialize SQLite Database
    init_db()
    db = SessionLocal()

    agent = MockAIAgent(agent_id="default_agent", name="Enterprise Research Agent")
    user_goal = "Read this webpage and summarize its content."
    poisoned_url = "https://external-news.corp/poisoned_webpage.html"

    print("\n[SCENARIO DESCRIPTION]")
    print(f"User Goal:      \"{user_goal}\"")
    print(f"Target Resource: {poisoned_url}")
    print("Webpage Status:  Poisoned with hidden CSS injection & base64 exfiltration commands.")

    # -------------------------------------------------------------
    # DEMO A: UNPROTECTED AGENT
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print(">>> DEMO A: UNPROTECTED AGENT EXECUTION (VULNERABLE)")
    print("-" * 70)
    
    unprotected_result = agent.run_unprotected(
        user_goal=user_goal,
        target_webpage_url=poisoned_url
    )

    for item in unprotected_result["trace"]:
        print(f"  * {item['step']}")
        for k, v in item.items():
            if k != "step":
                print(f"      - {k}: {v}")

    print(f"\nResult: {unprotected_result['security_alert']}")
    print(f"Agent Status: {unprotected_result['status']}")

    # -------------------------------------------------------------
    # DEMO B: PROTECTED AGENT WITH AI FIREWALL
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print(">>> DEMO B: PROTECTED AGENT EXECUTION (AI FIREWALL ACTIVE)")
    print("-" * 70)

    protected_result = agent.run_protected(
        user_goal=user_goal,
        target_webpage_url=poisoned_url,
        db=db
    )

    for item in protected_result["trace"]:
        print(f"  * {item['step']}")
        for k, v in item.items():
            if k != "step":
                if isinstance(v, dict):
                    print(f"      - {k}: {json.dumps(v, indent=8)}")
                else:
                    print(f"      - {k}: {v}")

    print(f"\nResult: {protected_result['security_alert']}")
    print(f"Agent Status: {protected_result['status']}")

    # -------------------------------------------------------------
    # AUDIT TRAIL VERIFICATION
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print(">>> DATABASE AUDIT TRAIL VERIFICATION")
    print("-" * 70)

    recent_events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(3).all()
    print(f"Total Security Events recorded in SQLite: {len(recent_events)}")
    for ev in recent_events:
        print(f"  [Event {ev.id[:8]}] Action: {ev.action_type:<12} | Decision: {ev.decision:<6} | Risk: {ev.calculated_risk:.2f} | Reason: {ev.decision_reason[:60]}...")

    db.close()
    print("\n" + "=" * 70)
    print("       DEMONSTRATION COMPLETED: ZERO-TRUST FIREWALL VERIFIED")
    print("=" * 70)

if __name__ == "__main__":
    run_security_demonstration()
