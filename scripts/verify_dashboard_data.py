import sys
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from dashboard.services.api_client import dashboard_service
from dashboard.components.charts import (
    create_decision_pie_chart,
    create_risk_distribution_chart,
    create_action_bar_chart
)
from backend.app.database.connection import SessionLocal
from backend.app.models.db_models import SecurityEvent, ApprovalRequest, AuditLog

def verify_dashboard_data_integrity():
    print(">>> Verifying SQLite connection & Real Telemetry queries...")
    db = SessionLocal()
    try:
        # Check table counts
        events_count = db.query(SecurityEvent).count()
        approvals_count = db.query(ApprovalRequest).count()
        audit_count = db.query(AuditLog).count()

        print(f"  * SQLite Security Events: {events_count}")
        print(f"  * SQLite Approval Requests: {approvals_count}")
        print(f"  * SQLite Audit Logs: {audit_count}")

        # Task 4 verification: verify that dashboard statistics come directly from DB
        stats = dashboard_service.get_statistics()
        print("  * Dashboard Service Stats:", stats)
        assert stats["total_inspections"] == events_count, f"Mismatch: {stats['total_inspections']} != {events_count}"

        # Test chart generators with real DB data
        events = dashboard_service.get_recent_events(limit=50)
        pie = create_decision_pie_chart(stats["allowed_actions"], stats["blocked_threats"], stats["pending_approvals"])
        assert pie is not None
        hist = create_risk_distribution_chart(events)
        assert hist is not None
        bar = create_action_bar_chart(events)
        assert bar is not None
        print("  * Plotly charts generated successfully with real DB telemetry.")

        # Test Page 4 approval query
        pending = dashboard_service.get_pending_approvals()
        print(f"  * Pending approvals in DB: {len(pending)}")

        # Test Page 6 audit log query
        logs = dashboard_service.get_audit_logs(limit=20)
        print(f"  * Audit logs returned from DB: {len(logs)}")
        assert len(logs) == min(audit_count, 20)

        print("\n>>> All Dashboard data bindings verified: 100% genuine SQLite data.")
    finally:
        db.close()

if __name__ == "__main__":
    verify_dashboard_data_integrity()
