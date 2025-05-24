# app/auth/security.py
from passlib.apache import HtpasswdFile
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)
security = HTTPBasic(auto_error=False) # auto_error=False로 설정하여 커스텀 예외 처리

# HtpasswdFile 객체는 한 번만 로드하거나, 필요시 리로드하는 로직을 추가할 수 있음
# 여기서는 간단하게 요청 시마다 파일을 읽도록 하지만, 성능을 위해 캐싱 고려 가능
def get_htpasswd_file():
    try:
        if settings.HTPASSWD_FILE.exists():
            return HtpasswdFile(str(settings.HTPASSWD_FILE))
        else:
            logger.warning(f"Htpasswd file not found at: {settings.HTPASSWD_FILE}")
            return None
    except Exception as e:
        logger.error(f"Error loading Htpasswd file: {e}")
        return None

async def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials is None:
        # 클라이언트가 WWW-Authenticate 헤더를 받고 로그인 프롬프트를 표시하도록 유도
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Basic"},
        )

    username = credentials.username
    password = credentials.password

    ht = get_htpasswd_file()
    if ht is None or not ht.check_password(username, password):
        logger.warning(f"Authentication failed for user: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"}, # 실패 시에도 WWW-Authenticate 헤더를 보내는 것이 좋음
        )
    logger.info(f"User '{username}' authenticated successfully.")
    return username # 인증 성공 시 사용자 이름 반환 (또는 사용자 객체)

# 이 예제에서는 'admin'이라는 사용자 이름을 가진 경우 관리자로 간주합니다.
# 실제 운영 환경에서는 역할 기반 접근 제어(RBAC) 등을 고려할 수 있습니다.
ADMIN_USERNAMES = ["admin"] # 관리자 사용자 이름 목록 (설정 파일로 옮겨도 좋습니다)

async def get_current_admin_user(current_user: str = Depends(authenticate_user)):
    if current_user not in ADMIN_USERNAMES:
        logger.warning(f"User '{current_user}' attempted admin access to a resource.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="You do not have permission to access this resource."
        )
    logger.info(f"Admin user '{current_user}' accessed an admin resource.")
    return current_user