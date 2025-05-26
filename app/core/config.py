# app/core/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache
from pathlib import Path

# BASE_DIR might still be useful for other things, but not strictly for an absolute HTPASSWD_FILE path
BASE_DIR = Path(__file__).resolve().parent.parent.parent 

class Settings(BaseSettings):
    DISTRIBUTION_REGISTRY_URL: str = "http://127.0.0.1:5000"
    API_TIMEOUT_SECONDS: int = 300
    HTPASSWD_FILE: Path = Path("/home/rosaria01/secret/.htpasswd") # 이전 단계에서 변경된 경로

    # SQLite 데이터베이스 URL 추가 (프로젝트 루트에 audit.db 파일로 생성)
    AUDIT_DATABASE_URL: str = f"sqlite:///{BASE_DIR}/audit.db"

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()