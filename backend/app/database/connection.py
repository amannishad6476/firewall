from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pathlib import Path
from ..config.settings import settings
from ..models.db_models import Base, Agent, SecurityPolicy

# SQLite database setup with thread safety
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    # Ensure database tables exist
    Base.metadata.create_all(bind=engine)
    
    # Seed default agents and policy if not present
    db = SessionLocal()
    try:
        # Check default agent
        existing_agent = db.query(Agent).filter(Agent.id == "default_agent").first()
        if not existing_agent:
            default_agent = Agent(
                id="default_agent",
                name="Default Assistant Agent",
                description="General assistant agent handling research and routine tool tasks",
                role="assistant",
                trust_level=0.5,
                is_active=True
            )
            analyst_agent = Agent(
                id="analyst_agent",
                name="Security Analyst Agent",
                description="Authorized agent for intelligence gathering and security audits",
                role="analyst",
                trust_level=0.75,
                is_active=True
            )
            admin_agent = Agent(
                id="admin_agent",
                name="Operations Admin Agent",
                description="Administrative agent with elevated operational privileges",
                role="admin",
                trust_level=0.9,
                is_active=True
            )
            db.add_all([default_agent, analyst_agent, admin_agent])
            db.commit()
            
        # Check security policy seed
        policy_path = Path(settings.POLICY_FILE_PATH)
        if policy_path.exists():
            with open(policy_path, "r", encoding="utf-8") as f:
                policy_content = f.read()
            
            existing_policy = db.query(SecurityPolicy).filter(SecurityPolicy.is_active == True).first()
            if not existing_policy:
                new_policy = SecurityPolicy(
                    version="1.0",
                    content_yaml=policy_content,
                    is_active=True
                )
                db.add(new_policy)
                db.commit()
    finally:
        db.close()
