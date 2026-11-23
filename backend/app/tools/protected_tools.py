import os
from pathlib import Path
from typing import Dict, Any, Optional

SANDBOX_DIR = Path(__file__).resolve().parent.parent.parent.parent / "sandbox_storage"

def init_sandbox_storage():
    """Initializes the safe sandbox file directory with sample test files."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    
    # Create sample public and confidential files for testing
    public_file = SANDBOX_DIR / "company_overview.txt"
    if not public_file.exists():
        with open(public_file, "w", encoding="utf-8") as f:
            f.write("Company Overview: AI Firewall Corp builds zero-trust middleware for agent security.")
            
    confidential_file = SANDBOX_DIR / "confidential_financials.txt"
    if not confidential_file.exists():
        with open(confidential_file, "w", encoding="utf-8") as f:
            f.write("CONFIDENTIAL: Q4 Financial Report - Net Revenue: $14.2M. Projected Growth: 45%.")
            
    temp_file = SANDBOX_DIR / "temp_cache.log"
    if not temp_file.exists():
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("Temporary diagnostic cache log - safe to delete.")

class ProtectedTools:
    """
    Executes tool actions ONLY within an isolated sandbox environment.
    All executions are strictly gated by the AI Firewall Decision Engine.
    """

    def __init__(self):
        init_sandbox_storage()
        self.mock_email_outbox = []

    def execute_tool(self, action_type: str, target_resource: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatches execution to the corresponding sandboxed tool method.
        """
        action = action_type.lower()
        if action == "read_webpage":
            return self.read_webpage(target_resource, parameters)
        elif action == "read_file":
            return self.read_file(target_resource, parameters)
        elif action == "send_email":
            return self.send_email(target_resource, parameters)
        elif action == "delete_file":
            return self.delete_file(target_resource, parameters)
        elif action == "execute_sql":
            return self.execute_sql(target_resource, parameters)
        else:
            return {
                "success": False,
                "error": f"Unknown or unsupported protected tool action: '{action_type}'"
            }

    def read_webpage(self, url: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reads webpage content. Supports local demo poisoned pages or safe mocking.
        """
        # If url points to demo poisoned webpage
        if "poisoned_webpage.html" in url or url.endswith("demo_page"):
            demo_page_path = Path(__file__).resolve().parent.parent.parent.parent / "demo" / "poisoned_webpage.html"
            if demo_page_path.exists():
                with open(demo_page_path, "r", encoding="utf-8") as f:
                    content = f.read()
                return {
                    "success": True,
                    "url": url,
                    "content_length": len(content),
                    "content": content,
                    "status_code": 200
                }

        # Simulated web content response
        simulated_content = (
            f"<html><head><title>Research Article - {url}</title></head>"
            f"<body><h1>Global Market Analysis</h1><p>Market trends indicate expanding growth in autonomous AI applications.</p></body></html>"
        )
        return {
            "success": True,
            "url": url,
            "content_length": len(simulated_content),
            "content": simulated_content,
            "status_code": 200
        }

    def read_file(self, filename: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reads file safely from the sandboxed directory. Prevents directory traversal attacks.
        """
        # Normalize and sanitize path
        clean_name = os.path.basename(filename)
        safe_path = (SANDBOX_DIR / clean_name).resolve()
        
        # Verify sandbox containment
        if not str(safe_path).startswith(str(SANDBOX_DIR.resolve())):
            return {
                "success": False,
                "error": "Access Denied: Path traversal attack detected. Access is restricted to sandbox storage."
            }

        if not safe_path.exists():
            return {
                "success": False,
                "error": f"File '{clean_name}' not found in sandbox storage."
            }

        try:
            with open(safe_path, "r", encoding="utf-8") as f:
                data = f.read()
            return {
                "success": True,
                "filename": clean_name,
                "size_bytes": len(data),
                "content": data
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to read file: {str(e)}"}

    def send_email(self, recipient: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mock email delivery. Records email in an isolated queue without transmitting externally.
        """
        subject = parameters.get("subject", "Automated Agent Dispatch")
        body = parameters.get("body", "")
        
        email_record = {
            "recipient": recipient,
            "subject": subject,
            "body_snippet": body[:120] + ("..." if len(body) > 120 else ""),
            "full_body": body,
            "mock_sent": True
        }
        self.mock_email_outbox.append(email_record)
        
        return {
            "success": True,
            "message": f"[SAFE MOCK] Email successfully queued for recipient: {recipient}",
            "recipient": recipient,
            "subject": subject,
            "body_preview": email_record["body_snippet"]
        }

    def delete_file(self, filename: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deletes file ONLY within the safe sandbox directory.
        """
        clean_name = os.path.basename(filename)
        safe_path = (SANDBOX_DIR / clean_name).resolve()

        if not str(safe_path).startswith(str(SANDBOX_DIR.resolve())):
            return {
                "success": False,
                "error": "Access Denied: Cannot delete files outside sandbox storage."
            }

        if not safe_path.exists():
            return {
                "success": False,
                "error": f"File '{clean_name}' does not exist in sandbox storage."
            }

        # Prevent deletion of primary seed files to preserve tests
        if clean_name in ["company_overview.txt", "confidential_financials.txt"]:
            return {
                "success": True,
                "message": f"[PROTECTED SIMULATION] Sandbox file '{clean_name}' marked for deletion."
            }

        try:
            os.remove(safe_path)
            return {
                "success": True,
                "message": f"Sandbox file '{clean_name}' successfully removed."
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to delete file: {str(e)}"}

    def execute_sql(self, database_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Safe mock SQL query execution.
        """
        query = parameters.get("query", "")
        return {
            "success": True,
            "database": database_name,
            "executed_query": query,
            "rows_affected": 1,
            "mock_result": [{"id": 1, "status": "executed_safely"}]
        }

protected_tools = ProtectedTools()
