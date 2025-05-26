# app/db/database.py
import sqlalchemy
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, DateTime, JSON
from datetime import datetime
import logging

from app.core.config import settings
from app.models.audit import AuditLogDBCreate # 감사 로그 생성용 모델

logger = logging.getLogger(__name__)

DATABASE_URL = settings.AUDIT_DATABASE_URL

# SQLAlchemy 엔진 생성
# connect_args={"check_same_thread": False}는 SQLite를 사용할 때 FastAPI(Starlette)의 비동기 환경에서 필요합니다.
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# 메타데이터 객체 생성
metadata = MetaData()

# 감사 로그 테이블 정의
audit_log_table = Table(
    "audit_log",
    metadata,
    Column("id", Integer, primary_key=True, index=True, autoincrement=True),
    Column("timestamp", DateTime, default=datetime.utcnow, index=True),
    Column("username", String, nullable=True, index=True),
    Column("action", String, index=True),
    Column("client_ip", String, nullable=True),
    Column("resource_type", String, nullable=True, index=True),
    Column("resource_name", String, nullable=True, index=True),
    Column("status", String, index=True),
    Column("details", JSON, nullable=True), # SQLite는 JSON 타입을 지원합니다 (최신 버전)
)

def create_db_and_tables():
    """ 데이터베이스와 테이블을 생성합니다 (이미 존재하면 생성하지 않음) """
    try:
        logger.info(f"Attempting to create database tables at {DATABASE_URL}")
        metadata.create_all(bind=engine)
        logger.info("Database tables created successfully (if they didn't exist).")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}", exc_info=True)
        # 프로덕션에서는 여기서 애플리케이션을 중지시키는 것을 고려할 수 있습니다.
        raise

# 감사 로그 기록 함수
async def log_audit_event(log_entry: AuditLogDBCreate):
    """ 감사 로그 항목을 데이터베이스에 기록합니다. """
    query = audit_log_table.insert().values(
        timestamp=log_entry.timestamp,
        username=log_entry.username,
        action=log_entry.action,
        client_ip=log_entry.client_ip,
        resource_type=log_entry.resource_type,
        resource_name=log_entry.resource_name,
        status=log_entry.status,
        details=log_entry.details,
    )
    try:
        # engine.begin()을 사용하여 컨텍스트 내에서 트랜잭션 관리
        with engine.begin() as connection:
            connection.execute(query)
        logger.info(f"Audit event logged: User='{log_entry.username}', Action='{log_entry.action}', Resource='{log_entry.resource_type}:{log_entry.resource_name}', Status='{log_entry.status}'")
    except Exception as e:
        # 로깅 실패가 주요 기능을 막아서는 안 되므로, 여기서는 오류만 기록하고 넘어갑니다.
        # 하지만 중요한 감사 정보 누락에 대한 알림 전략이 필요할 수 있습니다.
        logger.error(f"Failed to log audit event: {log_entry.model_dump_json()}. Error: {e}", exc_info=True)