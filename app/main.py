# app/main.py
from fastapi import FastAPI
import logging

from app.api.v2 import endpoints as v2_endpoints
from app.api.management import users as users_management_endpoints # 사용자 관리 라우터 임포트
from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="My Private Docker Registry Service",
    version="0.1.0"
)

# /v2 경로에 대한 라우터 포함
app.include_router(v2_endpoints.router, prefix="/v2", tags=["v2 Registry Proxy"])

# /users 경로에 대한 사용자 관리 라우터 포함
app.include_router(
    users_management_endpoints.router, 
    prefix="/users", 
    tags=["User Management"]
)


@app.get("/", tags=["Root"])
async def read_root():
    logger.info("Root path '/' accessed.")
    return {"message": "Welcome to My Private Docker Registry Service!"}

@app.on_event("startup")
async def startup_event():
    logger.info("Application startup...")
    logger.info(f"Proxying to Distribution Registry at: {settings.DISTRIBUTION_REGISTRY_URL}")
    if not settings.HTPASSWD_FILE.exists():
        logger.warning(f"HTPASSWD_FILE not found at {settings.HTPASSWD_FILE}. User authentication will fail.")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Application shutdown...")