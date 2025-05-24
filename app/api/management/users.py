# app/api/management/users.py
from fastapi import APIRouter, Depends, HTTPException, status, Body # Body 추가
from pydantic import BaseModel, Field # BaseModel, Field 추가
import logging
import subprocess # subprocess 모듈 임포트
import shlex # shlex 모듈 임포트 (명령어 인자 처리에 유용)

from app.auth.security import get_current_admin_user, get_htpasswd_file
from app.core.config import settings # settings 임포트

router = APIRouter()
logger = logging.getLogger(__name__)

# --- GET /users (이전에 구현한 내용) ---
@router.get("", summary="List all users")
async def list_users(
    admin_user: str = Depends(get_current_admin_user)
):
    ht = get_htpasswd_file()
    if ht is None:
        logger.error("Htpasswd file could not be loaded for listing users.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User database is not available."
        )
    users = ht.users()
    logger.info(f"Admin '{admin_user}' listed users: {users}")
    return {"users": users}

# --- POST /users (새로 추가할 내용) ---
class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, description="Username for the new user")
    password: str = Field(..., min_length=6, description="Password for the new user (min 6 chars)")

@router.post("", status_code=status.HTTP_201_CREATED, summary="Create a new user")
async def create_user(
    user_data: UserCreate,
    admin_user: str = Depends(get_current_admin_user) # 관리자 인증
):
    """
    Creates a new user in the htpasswd file.
    Only accessible by admin users.
    The password will be hashed using bcrypt.
    """
    ht = get_htpasswd_file()
    if ht is None:
        logger.error(f"Htpasswd file could not be loaded by admin '{admin_user}' for creating user '{user_data.username}'.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User database is not available."
        )

    if user_data.username in ht.users():
        logger.warning(f"Admin '{admin_user}' attempted to create existing user '{user_data.username}'.")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User '{user_data.username}' already exists."
        )

    # htpasswd 명령 실행하여 사용자 추가
    # htpasswd -B (bcrypt) -b (batch mode) <htpasswd_file> <username> <password>
    # shlex.quote를 사용하여 각 인자를 안전하게 처리 (특히 password에 특수문자가 있을 경우)
    command = [
        "htpasswd",
        "-B",  # Use bcrypt
        "-b",  # Batch mode (password on command line)
        shlex.quote(str(settings.HTPASSWD_FILE)),
        shlex.quote(user_data.username),
        shlex.quote(user_data.password)
    ]

    logger.info(f"Admin '{admin_user}' executing command to create user '{user_data.username}': {' '.join(command).replace(user_data.password, '********')}")

    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.info(f"User '{user_data.username}' created successfully by admin '{admin_user}'. Output: {process.stdout}")
        return {"message": f"User '{user_data.username}' created successfully."}
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create user '{user_data.username}' by admin '{admin_user}'. Command: {' '.join(e.cmd).replace(user_data.password, '********')}")
        logger.error(f"htpasswd stderr: {e.stderr}")
        logger.error(f"htpasswd stdout: {e.stdout}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user. htpasswd command failed: {e.stderr or e.stdout or 'Unknown error'}"
        )
    except FileNotFoundError:
        logger.error("htpasswd command not found. Ensure apache2-utils is installed and in PATH.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: htpasswd utility not found."
        )
    
@router.delete("/{username_to_delete}", status_code=status.HTTP_200_OK, summary="Delete a user")
async def delete_user(
    username_to_delete: str,
    admin_user: str = Depends(get_current_admin_user) # 관리자 인증
):
    """
    Deletes a user from the htpasswd file.
    Only accessible by admin users. An admin cannot delete themselves.
    """
    ht = get_htpasswd_file()
    if ht is None:
        logger.error(f"Htpasswd file could not be loaded by admin '{admin_user}' for deleting user '{username_to_delete}'.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User database is not available."
        )

    if username_to_delete not in ht.users():
        logger.warning(f"Admin '{admin_user}' attempted to delete non-existing user '{username_to_delete}'.")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username_to_delete}' not found."
        )

    if username_to_delete == admin_user:
        logger.warning(f"Admin '{admin_user}' attempted to delete themselves.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins cannot delete themselves."
        )

    # htpasswd 명령 실행하여 사용자 삭제
    # htpasswd -D <htpasswd_file> <username>
    command = [
        "htpasswd",
        "-D",  # Delete user
        shlex.quote(str(settings.HTPASSWD_FILE)),
        shlex.quote(username_to_delete)
    ]
    logger.info(f"Admin '{admin_user}' executing command to delete user '{username_to_delete}': {' '.join(command)}")

    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.info(f"User '{username_to_delete}' deleted successfully by admin '{admin_user}'. Output: {process.stdout}")
        return {"message": f"User '{username_to_delete}' deleted successfully."}
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to delete user '{username_to_delete}' by admin '{admin_user}'. Command: {' '.join(e.cmd)}")
        logger.error(f"htpasswd stderr: {e.stderr}")
        logger.error(f"htpasswd stdout: {e.stdout}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user. htpasswd command failed: {e.stderr or e.stdout or 'Unknown error'}"
        )
    except FileNotFoundError:
        logger.error("htpasswd command not found. Ensure apache2-utils is installed and in PATH.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: htpasswd utility not found."
        )