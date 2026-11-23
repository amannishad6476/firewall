import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from .config.settings import settings
from .database.connection import init_db
from .api.routes import router as api_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise-grade AI Agent Firewall, Taint Isolation & Security Monitoring Platform.",
    lifespan=lifespan
)

# CORS middleware for Streamlit or web UI integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Latency measurement middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000
    response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
    return response

# Root health endpoint
@app.get("/health", tags=["System"])
def root_health():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "mode": "Fail-Closed Active Enforcement"
    }

# Mount API V1 routes
app.include_router(api_router, prefix=settings.API_V1_PREFIX)
app.include_router(api_router)  # Also mount at root for /health and direct calls

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.FIREWALL_HOST, port=settings.FIREWALL_PORT, reload=True)
