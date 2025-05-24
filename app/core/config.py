# app/core/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache
from pathlib import Path

# BASE_DIR might still be useful for other things, but not strictly for an absolute HTPASSWD_FILE path
BASE_DIR = Path(__file__).resolve().parent.parent.parent 

class Settings(BaseSettings):
    DISTRIBUTION_REGISTRY_URL: str = "http://127.0.0.1:5000"
    API_TIMEOUT_SECONDS: int = 300
    # Update this line:
    HTPASSWD_FILE: Path = Path("/home/rosaria01/secret/.htpasswd")

    class Config:
        env_file = ".env" # If you use a .env file, you could also set HTPASSWD_FILE there
        env_file_encoding = 'utf-8'

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()