# app/auth/security.py
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.apache import HtpasswdFile # 또는 from passlib.apache_htpasswd import HtpasswdFile
import logging
from typing import Optional # Optional 임포트 추가

from app.core.config import settings
from app.db.database import log_audit_event # 감사 로그 기록 함수 임포트
from app.models.audit import AuditLogDBCreate # 감사 로그 모델 임포트

logger = logging.getLogger(__name__)
security = HTTPBasic(auto_error=False) # auto_error=False로 설정하여 커스텀 예외 처리

# 이 예제에서는 'admin'이라는 사용자 이름을 가진 경우 관리자로 간주합니다.
# 실제 운영 환경에서는 역할 기반 접근 제어(RBAC) 등을 고려할 수 있습니다.
ADMIN_USERNAMES = ["admin"] # 관리자 사용자 이름 목록 (설정 파일로 옮겨도 좋습니다)


def get_htpasswd_file():
    """
    .htpasswd 파일을 로드합니다.
    파일이 없거나 오류 발생 시 None을 반환합니다.
    """
    try:
        if settings.HTPASSWD_FILE.exists():
            return HtpasswdFile(str(settings.HTPASSWD_FILE))
        else:
            logger.warning(f"Htpasswd file not found at: {settings.HTPASSWD_FILE}")
            return None
    except Exception as e:
        logger.error(f"Error loading Htpasswd file: {e}", exc_info=True)
        return None

async def authenticate_user(
    request: Request, # Request 객체를 FastAPI가 주입하도록 추가
    credentials: Optional[HTTPBasicCredentials] = Depends(security) # Optional로 변경
):
    """
    HTTP Basic 인증을 사용하여 사용자를 인증합니다.
    인증 성공 시 사용자 이름을 반환하고, 실패 시 HTTPException을 발생시킵니다.
    로그인 시도 및 성공/실패에 대한 감사 로그를 기록합니다.
    """
    client_ip = request.client.host if request.client else "Unknown"

    if credentials is None:
        # 클라이언트가 WWW-Authenticate 헤더를 받고 로그인 프롬프트를 표시하도록 유도
        # 이 경우, 어떤 사용자가 시도했는지 알 수 없으므로 익명으로 실패 로그를 남기거나,
        # 클라이언트 IP 기반으로 시도 로그를 남길 수 있습니다.
        # 여기서는 간단히 예외만 발생시킵니다.
        logger.debug(f"Authentication attempt without credentials from IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    username = credentials.username
    password = credentials.password

    ht = get_htpasswd_file()
    if ht is None: # Htpasswd 파일 로드 실패
        logger.error(f"Htpasswd file not available for authentication attempt by user '{username}' from IP: {client_ip}")
        # 시스템 오류로 간주하고 로그인 시도 로그를 남길 수 있음
        log_entry_system_fail = AuditLogDBCreate(
            username=username, # 시도한 사용자 이름
            action="USER_LOGIN_ATTEMPT",
            client_ip=client_ip,
            status="FAILURE",
            details={"reason": "User authentication system unavailable (htpasswd file missing or unreadable)"}
        )
        await log_audit_event(log_entry_system_fail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, # 내부 서버 오류로 응답
            detail="User authentication system is currently unavailable.",
            # WWW-Authenticate 헤더는 클라이언트가 재시도하도록 유도할 수 있으므로, 여기서는 제외하는 것을 고려
        )

    if not ht.check_password(username, password):
        logger.warning(f"Authentication failed for user: '{username}' from IP: {client_ip}")
        # 로그인 실패 감사 로그
        log_entry_fail = AuditLogDBCreate(
            username=username, # 시도한 사용자 이름
            action="USER_LOGIN_ATTEMPT",
            client_ip=client_ip,
            status="FAILURE",
            details={"reason": "Incorrect username or password"}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    logger.info(f"User '{username}' authenticated successfully from IP: {client_ip}.")
    # 로그인 성공 감사 로그
    log_entry_success = AuditLogDBCreate(
        username=username,
        action="USER_LOGIN",
        client_ip=client_ip,
        status="SUCCESS"
    )
    await log_audit_event(log_entry_success)
    return username

async def get_current_admin_user(
    request: Request, # Request 객체 주입
    current_user: str = Depends(authenticate_user) # authenticate_user를 통해 먼저 인증
):
    """
    현재 인증된 사용자가 관리자인지 확인합니다.
    관리자가 아니면 HTTPException (403 Forbidden)을 발생시킵니다.
    관리자 접근 시도에 대한 감사 로그를 기록합니다.
    """
    client_ip = request.client.host if request.client else "Unknown"

    if current_user not in ADMIN_USERNAMES:
        logger.warning(f"User '{current_user}' from IP '{client_ip}' attempted admin access to a resource but is not an admin.")
        # 관리자 권한 없는 접근 시도 감사 로그
        log_entry_admin_fail = AuditLogDBCreate(
            username=current_user,
            action="ADMIN_ACCESS_DENIED",
            client_ip=client_ip,
            status="FAILURE",
            details={"reason": "User is not in the admin list."}
        )
        await log_audit_event(log_entry_admin_fail)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="You do not have permission to access this resource. Administrator privileges required."
        )
    
    # 관리자 접근 성공 로그는 각 관리자용 엔드포인트에서 특정 작업 성공 시 기록하는 것이 더 유용할 수 있습니다.
    # 여기서는 간단히 정보 로그만 남깁니다.
    logger.info(f"Admin user '{current_user}' from IP '{client_ip}' granted admin access.")
    return current_user
