# app/api/v2/endpoints.py
from fastapi import APIRouter, Request, HTTPException, Depends, status # status 추가
from fastapi.responses import StreamingResponse
import httpx
import logging
import json # 상세 로깅용 (이전 단계에서 추가)
import re # 경로 분석을 위한 정규표현식 모듈

from app.core.config import settings
from app.auth.security import authenticate_user # 사용자 인증 함수
from app.db.database import log_audit_event # 감사 로그 기록 함수 임포트
from app.models.audit import AuditLogDBCreate # 감사 로그 모델 임포트

router = APIRouter()
logger = logging.getLogger(__name__)

# 매니페스트 경로를 식별하기 위한 정규표현식
# 예: myimage/manifests/latest, myorg/myimage/manifests/sha256:abcdef...
MANIFEST_PATH_REGEX = re.compile(r"^(?P<image_name>.+)/manifests/(?P<reference>[^/]+)$")

@router.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_v2_requests(
    request: Request, # Request 객체는 이미 authenticate_user를 통해 주입됨
    path: str,
    current_user: str = Depends(authenticate_user) 
):
    target_url = f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/{path}"
    client_ip = request.client.host if request.client else "Unknown"
    
    # 감사 로그를 위한 기본 정보
    audit_action = None
    audit_resource_type = None
    audit_resource_name = None
    audit_details = {"path": f"/v2/{path}", "method": request.method}

    # 경로와 메소드를 분석하여 PULL 또는 PUSH 작업인지 판단
    manifest_match = MANIFEST_PATH_REGEX.match(path)
    if manifest_match:
        image_name_from_path = manifest_match.group("image_name")
        reference_from_path = manifest_match.group("reference")
        audit_resource_name = f"{image_name_from_path}:{reference_from_path}"
        audit_resource_type = "image_manifest"
        audit_details["target_image"] = image_name_from_path
        audit_details["target_reference"] = reference_from_path

        if request.method == "GET":
            audit_action = "IMAGE_PULL_MANIFEST_ATTEMPT" # PULL 시도 (manifest GET)
        elif request.method == "PUT":
            audit_action = "IMAGE_PUSH_MANIFEST_ATTEMPT" # PUSH 시도 (manifest PUT)
        elif request.method == "HEAD": # HEAD 요청도 PULL의 일부로 볼 수 있음
            audit_action = "IMAGE_MANIFEST_CHECK_ATTEMPT"
        elif request.method == "DELETE": # Manifest 직접 삭제 (이미지/태그 삭제 API에서 사용)
            audit_action = "IMAGE_MANIFEST_DELETE_ATTEMPT"
            # 이 경우는 이미 management API에서 더 구체적인 로그를 남기므로 중복될 수 있음.
            # 필요에 따라 여기서 로깅을 생략하거나, 세부 정보를 다르게 할 수 있음.

    # 상세 로깅 (이전과 동일)
    # client_request_headers = dict(request.headers)
    # logger.info(f"Authenticated user: {current_user} (IP: {client_ip})")
    # logger.info(f"--> Incoming Request to Proxy: {request.method} {request.url} HEADERS: {json.dumps(client_request_headers, indent=2)}")

    async with httpx.AsyncClient(timeout=settings.API_TIMEOUT_SECONDS) as client:
        proxy_request_headers = {key: value for key, value in request.headers.items() if key.lower() not in ['host', 'authorization']}
        # logger.info(f"--> Sending Request to Backend: {request.method} {target_url} HEADERS: {json.dumps(proxy_request_headers, indent=2)}")
        
        request_body_iterator = request.stream()

        try:
            upstream_response = await client.request(
                method=request.method,
                url=target_url,
                headers=proxy_request_headers,
                params=request.query_params,
                content=request_body_iterator,
                follow_redirects=False
            )

            # backend_response_headers = dict(upstream_response.headers)
            # logger.info(f"<-- Received Response from Backend: STATUS={upstream_response.status_code} HEADERS: {json.dumps(backend_response_headers, indent=2)}")
            
            response_headers_to_client = {key: value for key, value in upstream_response.headers.items() if key.lower() not in ['content-encoding', 'transfer-encoding', 'connection']}
            # logger.info(f"<-- Sending Response to Client: STATUS={upstream_response.status_code} HEADERS: {json.dumps(response_headers_to_client, indent=2)}")

            # 감사 로그 기록 (성공 시)
            if audit_action: # PULL 또는 PUSH 관련 작업으로 판단된 경우
                # 성공 시 액션 이름 변경 (예: _ATTEMPT 제거)
                final_audit_action = audit_action.replace("_ATTEMPT", "")
                # HEAD 요청은 성공해도 _CHECK로 유지 (PULL 완료는 아님)
                if audit_action == "IMAGE_MANIFEST_CHECK_ATTEMPT" and upstream_response.is_success:
                    final_audit_action = "IMAGE_MANIFEST_CHECK"
                
                # PUSH 성공 시 (PUT manifest)는 201 Created, PULL 성공 시 (GET manifest)는 200 OK
                if upstream_response.is_success: # 2xx 응답 코드
                    log_status_text = "SUCCESS" # 변수 이름 변경 (status 모듈과 충돌 방지)
                    # PUSH의 경우 응답 헤더에서 digest를 가져올 수 있음
                    if request.method == "PUT" and upstream_response.status_code == status.HTTP_201_CREATED:
                        final_audit_action = "IMAGE_PUSH_MANIFEST" # 더 명확한 액션
                        manifest_digest_from_header = upstream_response.headers.get("Docker-Content-Digest")
                        if manifest_digest_from_header:
                            audit_details["manifest_digest"] = manifest_digest_from_header
                    elif request.method == "GET" and upstream_response.status_code == status.HTTP_200_OK:
                        final_audit_action = "IMAGE_PULL_MANIFEST"
                        manifest_digest_from_header = upstream_response.headers.get("Docker-Content-Digest")
                        if manifest_digest_from_header:
                            audit_details["manifest_digest"] = manifest_digest_from_header

                    log_entry = AuditLogDBCreate(
                        username=current_user, action=final_audit_action, client_ip=client_ip,
                        resource_type=audit_resource_type, resource_name=audit_resource_name, 
                        status=log_status_text, details=audit_details # 변경된 변수 이름 사용
                    )
                    await log_audit_event(log_entry)
                else: # 성공하지 않은 응답 (4xx, 5xx)
                    log_status_text = "FAILURE" # 변수 이름 변경
                    audit_details["reason"] = f"Backend responded with {upstream_response.status_code}"
                    audit_details["backend_status_code"] = upstream_response.status_code
                    log_entry = AuditLogDBCreate(
                        username=current_user, action=audit_action, client_ip=client_ip, # 실패 시에는 _ATTEMPT 액션 사용
                        resource_type=audit_resource_type, resource_name=audit_resource_name, 
                        status=log_status_text, details=audit_details # 변경된 변수 이름 사용
                    )
                    await log_audit_event(log_entry)


            return StreamingResponse(
                upstream_response.aiter_bytes(),
                status_code=upstream_response.status_code,
                headers=response_headers_to_client,
                media_type=upstream_response.headers.get("content-type")
            )

        except httpx.RequestError as exc: # httpx 요청 자체의 오류 (네트워크 등)
            logger.error(f"Error proxying v2 request to {target_url} by user '{current_user}' (IP: {client_ip}): {exc}")
            if audit_action: # PULL 또는 PUSH 관련 작업으로 판단된 경우
                audit_details["reason"] = f"Network error or connection refused: {exc}"
                log_entry_fail = AuditLogDBCreate(
                    username=current_user, action=audit_action, client_ip=client_ip,
                    resource_type=audit_resource_type, resource_name=audit_resource_name, 
                    status="FAILURE", details=audit_details
                )
                await log_audit_event(log_entry_fail)
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Bad Gateway: Error connecting to upstream registry. {exc}")
        except Exception as e: # 기타 예외
            logger.error(f"Unexpected error in proxy_v2_requests for {target_url} by user '{current_user}' (IP: {client_ip}): {e}", exc_info=True)
            if audit_action:
                audit_details["reason"] = f"Unexpected proxy error: {e}"
                log_entry_fail = AuditLogDBCreate(
                    username=current_user, action=audit_action, client_ip=client_ip,
                    resource_type=audit_resource_type, resource_name=audit_resource_name,
                    status="FAILURE", details=audit_details
                )
                await log_audit_event(log_entry_fail)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred in the proxy: {e}")

