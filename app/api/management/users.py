# app/api/management/users.py
from fastapi import APIRouter, Depends, HTTPException, status, Body, Request
from pydantic import BaseModel, Field
import logging
import subprocess
import shlex # 명령어 인자 처리에 유용

from app.auth.security import get_current_admin_user, get_htpasswd_file # HtpasswdFile 로더도 가져옵니다.
from app.core.config import settings # 설정 임포트
from app.db.database import log_audit_event # 감사 로그 기록 함수 임포트
from app.models.audit import AuditLogDBCreate # 감사 로그 모델 임포트

router = APIRouter()
logger = logging.getLogger(__name__)

# --- Pydantic 모델 정의 ---
class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, description="새 사용자의 사용자 이름")
    password: str = Field(..., min_length=6, description="새 사용자의 비밀번호 (최소 6자)")

class UserResponse(BaseModel):
    users: list[str]

class MessageResponse(BaseModel):
    message: str

# --- API 엔드포인트 ---
@router.get(
    "", 
    response_model=UserResponse,
    summary="모든 사용자 목록 조회",
    description="htpasswd 파일에서 모든 사용자 이름 목록을 가져옵니다.\n\n관리자만 접근 가능합니다."
)
async def list_users(
    request: Request, # 감사 로그를 위한 Request 객체
    admin_user: str = Depends(get_current_admin_user) # 관리자 인증
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path}
    
    ht = get_htpasswd_file()
    if ht is None:
        logger.error(f"Admin '{admin_user}' (IP: {client_ip}) failed to list users: Htpasswd file could not be loaded.")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_LIST_ATTEMPT", client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": "User database (htpasswd file) not available"}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="사용자 데이터베이스를 사용할 수 없습니다."
        )
    
    users = ht.users()
    logger.info(f"Admin '{admin_user}' (IP: {client_ip}) listed users: {users}")
    
    log_entry_success = AuditLogDBCreate(
        username=admin_user, action="USER_LIST", client_ip=client_ip,
        status="SUCCESS", details={**action_details, "listed_user_count": len(users)}
    )
    await log_audit_event(log_entry_success)
    return {"users": users}


@router.post(
    "", 
    status_code=status.HTTP_201_CREATED, 
    response_model=MessageResponse,
    summary="새 사용자 생성",
    description="htpasswd 파일에 새 사용자를 생성합니다.\n\n관리자만 접근 가능합니다.\n비밀번호는 bcrypt로 해시됩니다."
)
async def create_user(
    request: Request, # 감사 로그를 위한 Request 객체
    user_data: UserCreate,
    admin_user: str = Depends(get_current_admin_user) # 관리자 인증
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_username": user_data.username}

    ht = get_htpasswd_file()
    if ht is None:
        logger.error(f"Admin '{admin_user}' (IP: {client_ip}) failed to create user '{user_data.username}': Htpasswd file could not be loaded.")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_CREATE_ATTEMPT", client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="FAILURE",
            details={**action_details, "reason": "User database (htpasswd file) not available"}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="사용자 데이터베이스를 사용할 수 없습니다."
        )

    if user_data.username in ht.users():
        logger.warning(f"Admin '{admin_user}' (IP: {client_ip}) attempted to create existing user '{user_data.username}'.")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_CREATE_ATTEMPT", client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="FAILURE",
            details={**action_details, "reason": f"User '{user_data.username}' already exists."}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"사용자 '{user_data.username}'는(은) 이미 존재합니다."
        )

    command = [
        "htpasswd",
        "-B",  # bcrypt 사용
        "-b",  # 배치 모드 (명령줄에서 비밀번호 전달)
        shlex.quote(str(settings.HTPASSWD_FILE)),
        shlex.quote(user_data.username),
        shlex.quote(user_data.password) # 비밀번호는 로그에서 마스킹됨
    ]
    
    # 로그에는 비밀번호를 마스킹하여 기록
    masked_command_str = ' '.join(command).replace(user_data.password, '********')
    logger.info(f"Admin '{admin_user}' (IP: {client_ip}) executing command to create user '{user_data.username}': {masked_command_str}")

    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        logger.info(f"User '{user_data.username}' created successfully by admin '{admin_user}'. htpasswd output: {process.stdout.strip()}")
        
        log_entry_success = AuditLogDBCreate(
            username=admin_user, action="USER_CREATE", client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="SUCCESS",
            details=action_details
        )
        await log_audit_event(log_entry_success)
        return {"message": f"사용자 '{user_data.username}'이(가) 성공적으로 생성되었습니다."}
    except subprocess.CalledProcessError as e:
        error_output = (e.stderr or e.stdout or "Unknown htpasswd error").strip()
        logger.error(f"Failed to create user '{user_data.username}' by admin '{admin_user}'. Command: {masked_command_str}. htpasswd error: {error_output}")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_CREATE_ATTEMPT", client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="FAILURE",
            details={**action_details, "reason": f"htpasswd 명령어 실패: {error_output}"}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"사용자 생성 실패. htpasswd 명령어 오류: {error_output}"
        )
    except FileNotFoundError:
        logger.error(f"htpasswd command not found when admin '{admin_user}' (IP: {client_ip}) tried to create user '{user_data.username}'. Ensure apache2-utils is installed and in PATH.")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_CREATE_ATTEMPT", client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="FAILURE",
            details={**action_details, "reason": "서버 설정 오류: htpasswd 유틸리티를 찾을 수 없습니다."}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="서버 설정 오류: htpasswd 유틸리티를 찾을 수 없습니다."
        )


@router.delete(
    "/{username_to_delete}", 
    response_model=MessageResponse,
    summary="사용자 삭제",
    description="htpasswd 파일에서 사용자를 삭제합니다.\n\n관리자만 접근 가능합니다.\n관리자는 자기 자신을 삭제할 수 없습니다."
)
async def delete_user(
    request: Request, # 감사 로그를 위한 Request 객체
    username_to_delete: str,
    admin_user: str = Depends(get_current_admin_user) # 관리자 인증
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_username": username_to_delete}

    ht = get_htpasswd_file()
    if ht is None:
        logger.error(f"Admin '{admin_user}' (IP: {client_ip}) failed to delete user '{username_to_delete}': Htpasswd file could not be loaded.")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_DELETE_ATTEMPT", client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": "User database (htpasswd file) not available"}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="사용자 데이터베이스를 사용할 수 없습니다."
        )

    if username_to_delete not in ht.users():
        logger.warning(f"Admin '{admin_user}' (IP: {client_ip}) attempted to delete non-existing user '{username_to_delete}'.")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_DELETE_ATTEMPT", client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": f"User '{username_to_delete}' not found."}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"사용자 '{username_to_delete}'을(를) 찾을 수 없습니다."
        )

    if username_to_delete == admin_user: # 자기 자신 삭제 방지
        logger.warning(f"Admin '{admin_user}' (IP: {client_ip}) attempted to delete themselves ('{username_to_delete}').")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_DELETE_ATTEMPT", client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": "Admins cannot delete themselves."}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자는 자기 자신을 삭제할 수 없습니다."
        )

    command = [
        "htpasswd",
        "-D",  # 사용자 삭제
        shlex.quote(str(settings.HTPASSWD_FILE)),
        shlex.quote(username_to_delete)
    ]
    logger.info(f"Admin '{admin_user}' (IP: {client_ip}) executing command to delete user '{username_to_delete}': {' '.join(command)}")

    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        logger.info(f"User '{username_to_delete}' deleted successfully by admin '{admin_user}'. htpasswd output: {process.stdout.strip()}")
        
        log_entry_success = AuditLogDBCreate(
            username=admin_user, action="USER_DELETE", client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="SUCCESS",
            details=action_details
        )
        await log_audit_event(log_entry_success)
        return {"message": f"사용자 '{username_to_delete}'이(가) 성공적으로 삭제되었습니다."}
    except subprocess.CalledProcessError as e:
        error_output = (e.stderr or e.stdout or "Unknown htpasswd error").strip()
        logger.error(f"Failed to delete user '{username_to_delete}' by admin '{admin_user}'. Command: {' '.join(command)}. htpasswd error: {error_output}")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_DELETE_ATTEMPT", client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": f"htpasswd 명령어 실패: {error_output}"}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"사용자 삭제 실패. htpasswd 명령어 오류: {error_output}"
        )
    except FileNotFoundError:
        logger.error(f"htpasswd command not found when admin '{admin_user}' (IP: {client_ip}) tried to delete user '{username_to_delete}'. Ensure apache2-utils is installed and in PATH.")
        log_entry_fail = AuditLogDBCreate(
            username=admin_user, action="USER_DELETE_ATTEMPT", client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": "서버 설정 오류: htpasswd 유틸리티를 찾을 수 없습니다."}
        )
        await log_audit_event(log_entry_fail)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="서버 설정 오류: htpasswd 유틸리티를 찾을 수 없습니다."
        )
