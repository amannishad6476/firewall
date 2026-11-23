import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI Agent Firewall & Security Monitoring Platform"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    
    FIREWALL_HOST: str = "127.0.0.1"
    FIREWALL_PORT: int = 8000
    
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/firewall.db"
    POLICY_FILE_PATH: str = str(BASE_DIR / "policies" / "security.yaml")
    
    FAIL_CLOSED: bool = True
    ENVIRONMENT: str = "development"
    SECRET_KEY: str = "dev-secret-key-123456789"
    
    # Risk calculation defaults
    DEFAULT_RISK_THRESHOLD_ALLOW: float = 0.30
    DEFAULT_RISK_THRESHOLD_ASK_HUMAN: float = 0.70
    
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
