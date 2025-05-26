# app/main.py
from fastapi import FastAPI
import logging

from app.api.v2 import endpoints as v2_endpoints
from app.api.management import users as users_management_endpoints
from app.api.management import images as images_management_endpoints
from app.api.management import audit as audit_management_endpoints # 감사 로그 라우터 임포트
from app.core.config import settings
from app.db.database import create_db_and_tables

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="My Private Docker Registry Service",
    version="0.1.0",
    description="""
    A private Docker Image Management Service.
    Allows users to push, pull, list, and manage Docker images.
    Provides user management and audit logging capabilities.
    """,
    contact={
        "name": "Service Administrator",
        "url": "http://example.com/contact",
        "email": "admin@example.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
)

@app.on_event("startup")
async def startup_event():
    logger.info("Application startup...")
    try:
        create_db_and_tables()
    except Exception as e:
        logger.critical(f"Could not create database tables during startup: {e}", exc_info=True)
    
    logger.info(f"Proxying to Distribution Registry at: {settings.DISTRIBUTION_REGISTRY_URL}")
    if not settings.HTPASSWD_FILE.exists():
        logger.warning(f"HTPASSWD_FILE not found at {settings.HTPASSWD_FILE}. User authentication will fail for some operations.")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Application shutdown...")

# API Routers
app.include_router(v2_endpoints.router, prefix="/v2", tags=["V2 Registry Proxy"])
app.include_router(users_management_endpoints.router, prefix="/users", tags=["User Management"])
app.include_router(images_management_endpoints.router, prefix="/images", tags=["Image Management"])
app.include_router(
    audit_management_endpoints.router, # 새로 추가된 부분
    prefix="/audit",                  # 새로 추가된 부분
    tags=["Audit Log Management"]     # 새로 추가된 부분
)

@app.get("/", tags=["Root"])
async def read_root():
    """
    Root endpoint for the service.
    Provides a welcome message and basic service information.
    """
    logger.info("Root path '/' accessed.")
    return {
        "message": "Welcome to My Private Docker Registry Service!",
        "version": app.version,
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }
