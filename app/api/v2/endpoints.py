# app/api/v2/endpoints.py
from fastapi import APIRouter, Request, HTTPException, Depends # Depends 추가
from fastapi.responses import StreamingResponse # Response는 StreamingResponse에 포함될 수 있음
import httpx
import logging
import json # 이전 단계에서 추가한 상세 로깅용

from app.core.config import settings
from app.auth.security import authenticate_user # 인증 함수 임포트

router = APIRouter()
logger = logging.getLogger(__name__)

@router.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_v2_requests(
    request: Request,
    path: str,
    # 현재 인증된 사용자 정보를 받지만, 여기서는 인증 통과 여부만 중요
    current_user: str = Depends(authenticate_user) 
):
    target_url = f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/{path}"

    # 클라이언트로부터 받은 요청 헤더 로깅
    client_request_headers = dict(request.headers)
    logger.info(f"Authenticated user: {current_user}") # 인증된 사용자 로그 추가
    logger.info(f"--> Incoming Request to Proxy: {request.method} {request.url} HEADERS: {json.dumps(client_request_headers, indent=2)}")

    async with httpx.AsyncClient(timeout=settings.API_TIMEOUT_SECONDS) as client:
        proxy_request_headers = {key: value for key, value in request.headers.items() if key.lower() not in ['host', 'authorization']}
        # 'authorization' 헤더는 프록시가 백엔드로 보낼 때 제거하거나, 
        # 백엔드 레지스트리가 별도의 인증을 사용한다면 그에 맞게 수정/전달해야 합니다.
        # 지금은 백엔드 레지스트리(localhost:5000)는 인증 없이 열려있다고 가정하고 제거합니다.

        # 백엔드로 보내는 요청 헤더 로깅
        logger.info(f"--> Sending Request to Backend: {request.method} {target_url} HEADERS: {json.dumps(proxy_request_headers, indent=2)}")

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

            # 백엔드로부터 받은 응답 헤더 로깅
            backend_response_headers = dict(upstream_response.headers)
            logger.info(f"<-- Received Response from Backend: STATUS={upstream_response.status_code} HEADERS: {json.dumps(backend_response_headers, indent=2)}")

            response_headers_to_client = {key: value for key, value in upstream_response.headers.items() if key.lower() not in ['content-encoding', 'transfer-encoding', 'connection']}

            # 클라이언트로 보내는 응답 헤더 로깅
            logger.info(f"<-- Sending Response to Client: STATUS={upstream_response.status_code} HEADERS: {json.dumps(response_headers_to_client, indent=2)}")

            return StreamingResponse(
                upstream_response.aiter_bytes(),
                status_code=upstream_response.status_code,
                headers=response_headers_to_client,
                media_type=upstream_response.headers.get("content-type")
            )

        except httpx.TimeoutException as exc:
            logger.error(f"Timeout proxying v2 request to {target_url}: {exc}")
            raise HTTPException(status_code=504, detail=f"Gateway Timeout: Upstream registry timed out. {exc}")
        except httpx.RequestError as exc:
            logger.error(f"Error proxying v2 request to {target_url}: {exc}")
            raise HTTPException(status_code=502, detail=f"Bad Gateway: Error connecting to upstream registry. {exc}")