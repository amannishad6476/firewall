import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.agents.mock_agent import MockAIAgent, mock_agent

if __name__ == "__main__":
    print("Mock AI Agent initialized successfully.")
