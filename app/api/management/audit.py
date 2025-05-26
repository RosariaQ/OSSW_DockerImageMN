# app/api/management/audit.py
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy import select, desc, and_ # SQLAlchemy의 select, desc, and_ 사용
from typing import List, Optional

from app.auth.security import get_current_admin_user
from app.db.database import engine, audit_log_table # DB 엔진과 테이블 직접 사용
from app.models.audit import AuditLogDB # DB 조회 결과용 Pydantic 모델
from app.core.config import settings # 설정 (필요시)

import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get(
    "",
    response_model=List[AuditLogDB],
    summary="감사 로그 조회",
    description="지정된 조건(사용자, 이미지 이름)에 따라 감사 로그를 조회합니다.\n\n관리자만 접근 가능합니다."
)
async def get_audit_logs(
    request: Request, # 클라이언트 IP 로깅 등 잠재적 사용을 위해 추가 (현재는 직접 사용 안함)
    admin_user: str = Depends(get_current_admin_user), # 관리자 인증
    user: Optional[str] = Query(None, description="로그를 필터링할 사용자 이름."),
    image_name: Optional[str] = Query(None, alias="image", description="로그를 필터링할 이미지 이름 (부분 일치 가능)."),
    action: Optional[str] = Query(None, description="로그를 필터링할 작업 유형 (예: USER_LOGIN, IMAGE_PUSH_MANIFEST)."),
    limit: int = Query(100, ge=1, le=1000, description="반환할 최대 로그 수."),
    offset: int = Query(0, ge=0, description="결과를 건너뛸 오프셋 (페이지네이션용).")
):
    client_ip = request.client.host if request.client else "Unknown"
    logger.info(f"Admin '{admin_user}' (IP: {client_ip}) requested audit logs with filters: user='{user}', image='{image_name}', action='{action}', limit={limit}, offset={offset}")

    # 기본 SELECT 쿼리 구성
    query = select(audit_log_table)
    
    # 필터 조건들을 담을 리스트
    filter_conditions = []

    if user:
        filter_conditions.append(audit_log_table.c.username == user)
    
    if image_name:
        # 이미지 이름은 resource_name 필드에서 부분 일치(like)로 검색
        # 예: 'myimage'로 검색 시 'myimage:latest', 'myorg/myimage:v1' 등이 검색될 수 있도록
        filter_conditions.append(audit_log_table.c.resource_name.like(f"%{image_name}%"))
        # 또는 더 구체적으로 resource_type도 함께 고려할 수 있습니다.
        # filter_conditions.append(
        #     or_(
        #         (audit_log_table.c.resource_type == "image_manifest") & audit_log_table.c.resource_name.contains(image_name),
        #         (audit_log_table.c.resource_type == "image_repository") & audit_log_table.c.resource_name.contains(image_name),
        #         (audit_log_table.c.resource_type == "image_tag") & audit_log_table.c.resource_name.contains(image_name)
        #     )
        # )

    if action:
        filter_conditions.append(audit_log_table.c.action == action)

    # 모든 필터 조건이 있다면 쿼리에 추가
    if filter_conditions:
        query = query.where(and_(*filter_conditions)) # and_를 사용하여 여러 조건을 결합

    # 정렬 (최신 로그부터) 및 페이지네이션
    query = query.order_by(desc(audit_log_table.c.timestamp)).limit(limit).offset(offset)

    logs = []
    try:
        with engine.connect() as connection:
            result_proxy = connection.execute(query)
            # SQLAlchemy 2.0 스타일에서는 result_proxy가 Row 객체들을 반환
            # Pydantic 모델로 변환하기 위해 각 Row를 딕셔너리로 변환 후 모델에 전달
            for row in result_proxy.mappings(): # .mappings()를 사용하면 딕셔너리처럼 접근 가능
                logs.append(AuditLogDB.model_validate(row)) # Pydantic v2: model_validate (이전: from_orm)
            
            # 또는 rows = result_proxy.fetchall() 후 루프 돌며 변환
            # for row in rows:
            #     logs.append(AuditLogDB(**row._asdict())) # row를 딕셔너리로 변환

    except Exception as e:
        logger.error(f"Error querying audit logs for admin '{admin_user}': {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="감사 로그를 조회하는 중 오류가 발생했습니다."
        )

    logger.info(f"Returning {len(logs)} audit log entries for admin '{admin_user}'.")
    return logs
