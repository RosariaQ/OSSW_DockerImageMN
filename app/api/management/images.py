# app/api/management/images.py
from fastapi import APIRouter, Depends, HTTPException, status, Path as FastAPIPath, Query, Request # Request 추가
from pydantic import BaseModel # BaseModel 임포트 추가
import httpx
import logging
from typing import Optional, List, Dict, Any

from app.core.config import settings
# authenticate_user 또는 get_current_admin_user를 상황에 맞게 사용
from app.auth.security import authenticate_user, get_current_admin_user 
from app.db.database import log_audit_event # 감사 로그 기록 함수 임포트
from app.models.audit import AuditLogDBCreate # 감사 로그 모델 임포트

router = APIRouter()
logger = logging.getLogger(__name__)

# --- API 응답 모델 (선택 사항이지만, API 문서를 위해 좋음) ---
class ImageTagsResponse(BaseModel):
    name: str
    tags: List[str]

class ImageRepositoriesResponse(BaseModel):
    repositories: List[str]
    pagination_info: Dict[str, Any] | str

class ImageDeletionResponse(BaseModel):
    message: str
    deleted_manifests: Optional[List[Dict[str, Any]]] = None
    errors: Optional[List[Dict[str, Any]]] = None

class TagDeletionResponse(BaseModel):
    message: str

# --- API 엔드포인트 ---
@router.get(
    "/{image_name:path}/tags", 
    response_model=ImageTagsResponse,
    summary="특정 이미지의 태그 목록 조회",
    description="백엔드 Docker Registry에서 지정된 이미지의 태그 목록을 가져옵니다.\n\n인증이 필요합니다."
)
async def list_image_tags(
    request: Request, # 감사 로그용
    image_name: str = FastAPIPath(
        ..., 
        title="이미지 이름",
        description="이미지의 이름으로, 슬래시를 포함할 수 있습니다 (예: 'myorg/myimage')."
    ),
    # 이 API는 일반 사용자도 접근 가능하도록 authenticate_user를 사용할 수 있습니다.
    # 여기서는 관리자만 접근 가능하도록 get_current_admin_user를 사용합니다. 요구사항에 따라 변경하세요.
    current_user: str = Depends(get_current_admin_user) 
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_image": image_name}
    
    tags_list_url = f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/{image_name}/tags/list"
    logger.info(f"User '{current_user}' (IP: {client_ip}) fetching tags for image '{image_name}' from '{tags_list_url}'")

    async with httpx.AsyncClient(timeout=settings.API_TIMEOUT_SECONDS) as client:
        try:
            response = await client.get(tags_list_url)
            response.raise_for_status() 
            tags_data = response.json()
            
            log_entry = AuditLogDBCreate(
                username=current_user, action="IMAGE_TAGS_LIST", client_ip=client_ip,
                resource_type="image_tags", resource_name=image_name, status="SUCCESS",
                details={**action_details, "tag_count": len(tags_data.get("tags", []))}
            )
            await log_audit_event(log_entry)
            logger.info(f"Successfully fetched tags for '{image_name}': {tags_data.get('tags')}")
            return tags_data
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            error_detail = f"Backend responded with {status_code}"
            if status_code == status.HTTP_404_NOT_FOUND:
                error_detail = f"Image '{image_name}' not found in backend registry."
                logger.warning(f"{error_detail} URL: {tags_list_url}")
            else:
                logger.error(f"Error fetching tags for '{image_name}' from backend. Status: {status_code}, Response: {exc.response.text}")

            log_entry_fail = AuditLogDBCreate(
                username=current_user, action="IMAGE_TAGS_LIST_ATTEMPT", client_ip=client_ip,
                resource_type="image_tags", resource_name=image_name, status="FAILURE",
                details={**action_details, "reason": error_detail, "backend_status_code": status_code}
            )
            await log_audit_event(log_entry_fail)
            
            if status_code == status.HTTP_404_NOT_FOUND:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"이미지 '{image_name}'을(를) 찾을 수 없습니다.")
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"백엔드 레지스트리와 통신 중 오류: {status_code}")
        except httpx.RequestError as exc:
            logger.error(f"RequestError while fetching tags for '{image_name}': {exc}")
            log_entry_fail = AuditLogDBCreate(
                username=current_user, action="IMAGE_TAGS_LIST_ATTEMPT", client_ip=client_ip,
                resource_type="image_tags", resource_name=image_name, status="FAILURE",
                details={**action_details, "reason": f"Network error: {exc}"}
            )
            await log_audit_event(log_entry_fail)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"백엔드 레지스트리와 통신 중 네트워크 오류: {exc}")
        except Exception as exc:
            logger.exception(f"Unexpected error fetching tags for '{image_name}': {exc}")
            log_entry_fail = AuditLogDBCreate(
                username=current_user, action="IMAGE_TAGS_LIST_ATTEMPT", client_ip=client_ip,
                resource_type="image_tags", resource_name=image_name, status="FAILURE",
                details={**action_details, "reason": f"Unexpected error: {exc}"}
            )
            await log_audit_event(log_entry_fail)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="예기치 않은 오류가 발생했습니다.")


@router.get(
    "", 
    response_model=ImageRepositoriesResponse,
    summary="레지스트리의 모든 이미지 (리포지토리) 목록 조회",
    description="백엔드 Docker Registry에서 모든 이미지 리포지토리 목록을 가져옵니다.\n\n'n'과 'last' 쿼리 파라미터를 사용하여 페이지네이션을 지원합니다.\n인증이 필요합니다."
)
async def list_all_images(
    request: Request, # 감사 로그용
    current_user: str = Depends(get_current_admin_user), # 관리자만 접근
    n: Optional[int] = Query(None, description="결과 수 제한."),
    last: Optional[str] = Query(None, description="이전 결과의 마지막 리포지토리 이름 (페이지네이션용).")
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "params": {"n": n, "last": last}}

    catalog_url = f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/_catalog"
    params = {}
    if n is not None: params["n"] = n
    if last is not None: params["last"] = last
    
    logger.info(f"User '{current_user}' (IP: {client_ip}) fetching image catalog from '{catalog_url}' with params: {params}")

    async with httpx.AsyncClient(timeout=settings.API_TIMEOUT_SECONDS) as client:
        try:
            response = await client.get(catalog_url, params=params)
            response.raise_for_status()
            catalog_data = response.json()
            repositories = catalog_data.get("repositories", [])
            
            link_header = response.headers.get("Link")
            next_page_info: Dict[str, Any] = {} # 타입 명시
            if link_header and 'rel="next"' in link_header:
                try:
                    next_page_info["next_link_header_exists"] = True
                    # 실제 Link 헤더 파싱 로직은 더 복잡할 수 있음
                    logger.info(f"Pagination 'Link' header found: {link_header}")
                except Exception:
                    logger.warning(f"Could not parse 'Link' header for pagination: {link_header}")
            
            log_entry = AuditLogDBCreate(
                username=current_user, action="IMAGE_CATALOG_LIST", client_ip=client_ip,
                status="SUCCESS", details={**action_details, "repository_count": len(repositories)}
            )
            await log_audit_event(log_entry)
            logger.info(f"Successfully fetched image catalog. Count: {len(repositories)}")
            return {"repositories": repositories, "pagination_info": next_page_info if next_page_info else "No further pages indicated by Link header."}
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            error_detail = f"Backend responded with {status_code}"
            logger.error(f"Error fetching image catalog from backend. Status: {status_code}, Response: {exc.response.text}")
            log_entry_fail = AuditLogDBCreate(
                username=current_user, action="IMAGE_CATALOG_LIST_ATTEMPT", client_ip=client_ip,
                status="FAILURE", details={**action_details, "reason": error_detail, "backend_status_code": status_code}
            )
            await log_audit_event(log_entry_fail)
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"백엔드 레지스트리와 통신 중 오류: {status_code}")
        except httpx.RequestError as exc:
            logger.error(f"RequestError while fetching image catalog: {exc}")
            log_entry_fail = AuditLogDBCreate(
                username=current_user, action="IMAGE_CATALOG_LIST_ATTEMPT", client_ip=client_ip,
                status="FAILURE", details={**action_details, "reason": f"Network error: {exc}"}
            )
            await log_audit_event(log_entry_fail)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"백엔드 레지스트리와 통신 중 네트워크 오류: {exc}")
        except Exception as exc:
            logger.exception(f"Unexpected error fetching image catalog: {exc}")
            log_entry_fail = AuditLogDBCreate(
                username=current_user, action="IMAGE_CATALOG_LIST_ATTEMPT", client_ip=client_ip,
                status="FAILURE", details={**action_details, "reason": f"Unexpected error: {exc}"}
            )
            await log_audit_event(log_entry_fail)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="예기치 않은 오류가 발생했습니다.")


@router.delete(
    "/{image_name:path}", 
    response_model=ImageDeletionResponse,
    status_code=status.HTTP_200_OK, # 성공 시 200 또는 202 (Accepted)도 가능
    summary="이미지 (모든 매니페스트) 삭제",
    description="이미지 리포지토리와 관련된 모든 매니페스트를 삭제합니다.\n\n이는 이미지를 사용할 수 없게 만듭니다. 실제 blob 가비지 컬렉션은 백엔드 레지스트리에서 별도로 실행해야 합니다.\n관리자 인증이 필요합니다."
)
async def delete_image_repository(
    request: Request, # 감사 로그용
    image_name: str = FastAPIPath(
        ...,
        title="이미지 이름",
        description="삭제할 이미지 리포지토리의 이름 (예: 'myorg/myimage')."
    ),
    admin_user: str = Depends(get_current_admin_user) # 관리자만 삭제 가능
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_image": image_name}
    logger.info(f"Admin '{admin_user}' (IP: {client_ip}) attempting to delete image repository '{image_name}'.")

    deleted_manifests_log: List[Dict[str, Any]] = []
    errors_deleting_log: List[Dict[str, Any]] = []
    overall_status = "SUCCESS" # 기본 상태

    async with httpx.AsyncClient(timeout=settings.API_TIMEOUT_SECONDS) as client:
        tags_list_url = f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/{image_name}/tags/list"
        try:
            tags_response = await client.get(tags_list_url)
            if tags_response.status_code == status.HTTP_404_NOT_FOUND:
                logger.info(f"Image repository '{image_name}' not found or has no tags. Considering it deleted for admin '{admin_user}'.")
                # 이미 존재하지 않는 경우도 성공으로 간주하고 로그 남길 수 있음
                log_entry_not_found = AuditLogDBCreate(
                    username=admin_user, action="IMAGE_REPO_DELETE", client_ip=client_ip,
                    resource_type="image_repository", resource_name=image_name, status="SUCCESS", # 또는 "NOT_APPLICABLE"
                    details={**action_details, "reason": "Repository not found or no tags, nothing to delete."}
                )
                await log_audit_event(log_entry_not_found)
                return {"message": f"이미지 리포지토리 '{image_name}'을(를) 찾을 수 없거나 삭제할 태그가 없습니다."}
            tags_response.raise_for_status()
            tags_data = tags_response.json()
            tags: List[str] = tags_data.get("tags", [])
            if not tags:
                logger.info(f"Image repository '{image_name}' has no tags. Nothing to delete for admin '{admin_user}'.")
                log_entry_no_tags = AuditLogDBCreate(
                    username=admin_user, action="IMAGE_REPO_DELETE", client_ip=client_ip,
                    resource_type="image_repository", resource_name=image_name, status="SUCCESS", # 또는 "NOT_APPLICABLE"
                    details={**action_details, "reason": "Repository has no tags."}
                )
                await log_audit_event(log_entry_no_tags)
                return {"message": f"이미지 리포지토리 '{image_name}'에 태그가 없습니다."}
        except Exception as e_tags: # 태그 목록 조회 실패
            logger.error(f"Failed to list tags for '{image_name}' during delete by admin '{admin_user}'. Error: {e_tags}")
            log_entry_fail_tags = AuditLogDBCreate(
                username=admin_user, action="IMAGE_REPO_DELETE_ATTEMPT", client_ip=client_ip,
                resource_type="image_repository", resource_name=image_name, status="FAILURE",
                details={**action_details, "reason": f"Failed to list tags before deletion: {e_tags}"}
            )
            await log_audit_event(log_entry_fail_tags)
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="삭제 전 태그 목록 조회 실패.")

        for tag in tags:
            manifest_digest = None # 루프 내에서 초기화
            try:
                head_headers = {"Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"}
                manifest_head_response = await client.head(f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/{image_name}/manifests/{tag}", headers=head_headers)
                
                if manifest_head_response.status_code == status.HTTP_404_NOT_FOUND:
                    logger.warning(f"Manifest for tag '{tag}' in '{image_name}' not found by admin '{admin_user}'. Skipping.")
                    errors_deleting_log.append({"tag": tag, "error": "Manifest not found (404)."})
                    overall_status = "PARTIAL_FAILURE"
                    continue
                manifest_head_response.raise_for_status()
                manifest_digest = manifest_head_response.headers.get("Docker-Content-Digest")

                if not manifest_digest:
                    logger.error(f"Could not get Docker-Content-Digest for tag '{tag}' in '{image_name}' for admin '{admin_user}'. Headers: {manifest_head_response.headers}")
                    errors_deleting_log.append({"tag": tag, "error": "Could not retrieve manifest digest."})
                    overall_status = "PARTIAL_FAILURE"
                    continue
                
                delete_manifest_url = f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/{image_name}/manifests/{manifest_digest}"
                logger.info(f"Admin '{admin_user}' attempting to delete manifest '{manifest_digest}' (tag: '{tag}') for image '{image_name}'. URL: {delete_manifest_url}")
                delete_response = await client.delete(delete_manifest_url)

                if delete_response.status_code == status.HTTP_202_ACCEPTED:
                    logger.info(f"Successfully deleted manifest '{manifest_digest}' (tag: '{tag}') for image '{image_name}' by admin '{admin_user}'.")
                    deleted_manifests_log.append({"tag": tag, "digest": manifest_digest, "status": "deleted"})
                elif delete_response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
                    err_msg = "Deletion not allowed (405). Check registry config."
                    logger.error(f"Manifest deletion not allowed for '{manifest_digest}' (tag: '{tag}') by admin '{admin_user}'. {err_msg}")
                    errors_deleting_log.append({"tag": tag, "digest": manifest_digest, "error": err_msg})
                    overall_status = "FAILURE" # 하나라도 405면 전체 실패로 간주 가능
                else: # 404 포함 기타 오류
                    delete_response.raise_for_status() # 예외 발생시켜 아래에서 처리

            except httpx.HTTPStatusError as exc_del:
                err_msg = f"HTTP error {exc_del.response.status_code}"
                logger.error(f"HTTPStatusError deleting manifest for tag '{tag}' in '{image_name}' by admin '{admin_user}'. Status: {exc_del.response.status_code}, Digest: {manifest_digest or 'N/A'}")
                errors_deleting_log.append({"tag": tag, "digest": manifest_digest or 'N/A', "error": err_msg})
                overall_status = "PARTIAL_FAILURE" if overall_status != "FAILURE" else "FAILURE"
            except Exception as exc_del_other:
                err_msg = f"Unexpected error: {exc_del_other}"
                logger.exception(f"Unexpected error deleting manifest for tag '{tag}' in '{image_name}' by admin '{admin_user}': {exc_del_other}")
                errors_deleting_log.append({"tag": tag, "digest": manifest_digest or 'N/A', "error": err_msg})
                overall_status = "PARTIAL_FAILURE" if overall_status != "FAILURE" else "FAILURE"
        
        # 최종 감사 로그 기록
        final_log_details = {
            **action_details,
            "deleted_count": len(deleted_manifests_log),
            "error_count": len(errors_deleting_log),
            "errors_summary": [e["error"] for e in errors_deleting_log[:3]] # 처음 3개 오류 요약
        }
        log_entry_final = AuditLogDBCreate(
            username=admin_user, action="IMAGE_REPO_DELETE", client_ip=client_ip,
            resource_type="image_repository", resource_name=image_name, status=overall_status,
            details=final_log_details
        )
        await log_audit_event(log_entry_final)

        if not deleted_manifests_log and not errors_deleting_log:
             return {"message": f"이미지 리포지토리 '{image_name}'에 대해 처리할 매니페스트가 없거나 이미 처리되었습니다."}

        return {
            "message": f"이미지 리포지토리 '{image_name}'에 대한 삭제 작업이 완료되었습니다.",
            "deleted_manifests": deleted_manifests_log,
            "errors": errors_deleting_log
        }


@router.delete(
    "/{image_name:path}/tags/{tag_name}", 
    response_model=TagDeletionResponse,
    status_code=status.HTTP_200_OK, 
    summary="이미지에서 특정 태그 삭제",
    description="이미지 리포지토리에서 특정 태그(해당 태그의 매니페스트 삭제)를 삭제합니다.\n\n관리자 인증이 필요합니다."
)
async def delete_image_tag(
    request: Request, # 감사 로그용
    image_name: str = FastAPIPath(
        ...,
        title="이미지 이름",
        description="이미지 리포지토리의 이름 (예: 'myorg/myimage')."
    ),
    tag_name: str = FastAPIPath(
        ...,
        title="태그 이름",
        description="삭제할 특정 태그."
    ),
    admin_user: str = Depends(get_current_admin_user) # 관리자만 삭제 가능
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_image": image_name, "target_tag": tag_name}
    logger.info(f"Admin '{admin_user}' (IP: {client_ip}) attempting to delete tag '{tag_name}' from image '{image_name}'.")

    manifest_digest = None # try 블록 밖에서 선언

    async with httpx.AsyncClient(timeout=settings.API_TIMEOUT_SECONDS) as client:
        try:
            head_headers = {
                "Accept": ", ".join([
                    "application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.oci.image.index.v1+json"
                ])
            }
            manifest_url_by_tag = f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/{image_name}/manifests/{tag_name}"
            head_response = await client.head(manifest_url_by_tag, headers=head_headers)

            if head_response.status_code == status.HTTP_404_NOT_FOUND:
                logger.warning(f"Tag '{tag_name}' or image '{image_name}' not found for admin '{admin_user}'. Nothing to delete.")
                log_entry_404 = AuditLogDBCreate(
                    username=admin_user, action="IMAGE_TAG_DELETE_ATTEMPT", client_ip=client_ip,
                    resource_type="image_tag", resource_name=f"{image_name}:{tag_name}", status="FAILURE",
                    details={**action_details, "reason": "Tag or image not found."}
                )
                await log_audit_event(log_entry_404)
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"이미지 '{image_name}'의 태그 '{tag_name}'을(를) 찾을 수 없습니다.")
            head_response.raise_for_status()

            manifest_digest = head_response.headers.get("Docker-Content-Digest")
            if not manifest_digest:
                logger.error(f"Could not get Docker-Content-Digest for tag '{tag_name}' on image '{image_name}' for admin '{admin_user}'.")
                log_entry_no_digest = AuditLogDBCreate(
                    username=admin_user, action="IMAGE_TAG_DELETE_ATTEMPT", client_ip=client_ip,
                    resource_type="image_tag", resource_name=f"{image_name}:{tag_name}", status="FAILURE",
                    details={**action_details, "reason": "Failed to retrieve manifest digest for the tag."}
                )
                await log_audit_event(log_entry_no_digest)
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="태그에 대한 매니페스트 digest를 가져오지 못했습니다.")
            logger.info(f"Found manifest digest '{manifest_digest}' for tag '{tag_name}' on image '{image_name}'.")

            delete_manifest_url_by_digest = f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/{image_name}/manifests/{manifest_digest}"
            logger.info(f"Admin '{admin_user}' attempting to delete manifest '{manifest_digest}' (tag: '{tag_name}') for image '{image_name}'. URL: {delete_manifest_url_by_digest}")
            
            delete_response = await client.delete(delete_manifest_url_by_digest)

            if delete_response.status_code == status.HTTP_202_ACCEPTED:
                logger.info(f"Successfully deleted manifest '{manifest_digest}' (associated with tag '{tag_name}') from image '{image_name}' by admin '{admin_user}'.")
                log_entry_success = AuditLogDBCreate(
                    username=admin_user, action="IMAGE_TAG_DELETE", client_ip=client_ip,
                    resource_type="image_tag", resource_name=f"{image_name}:{tag_name}", 
                    status="SUCCESS", details={**action_details, "deleted_manifest_digest": manifest_digest}
                )
                await log_audit_event(log_entry_success)
                return {"message": f"이미지 '{image_name}'의 태그 '{tag_name}' (매니페스트 {manifest_digest})이(가) 성공적으로 삭제되었습니다."}
            
            # 405, 404 (삭제 시점) 등 다른 오류는 여기서 처리
            delete_response.raise_for_status() # 여기서 예외를 발생시켜 아래에서 잡도록 함

        except httpx.HTTPStatusError as exc_del: # HEAD 또는 DELETE 요청에서 발생한 HTTP 오류
            status_code = exc_del.response.status_code
            error_reason = f"Backend responded with {status_code}"
            if status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
                error_reason = "Manifest deletion is not allowed by the backend registry. Check registry configuration."
            
            logger.error(f"HTTPStatusError during tag deletion for '{image_name}:{tag_name}' by admin '{admin_user}'. Status: {status_code}, Digest: {manifest_digest or 'N/A'}, Reason: {error_reason}")
            log_entry_fail = AuditLogDBCreate(
                username=admin_user, action="IMAGE_TAG_DELETE_ATTEMPT", client_ip=client_ip,
                resource_type="image_tag", resource_name=f"{image_name}:{tag_name}", status="FAILURE",
                details={**action_details, "reason": error_reason, "backend_status_code": status_code, "manifest_digest_attempted": manifest_digest}
            )
            await log_audit_event(log_entry_fail)
            
            if status_code == status.HTTP_404_NOT_FOUND and exc_del.request.method == "DELETE": # 삭제 시점에 404
                 raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="삭제할 매니페스트를 찾을 수 없습니다. 다른 프로세스에 의해 이미 삭제되었을 수 있습니다.")
            elif status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
                 raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=error_reason) # 또는 502
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"태그 삭제 실패: 백엔드 응답 {status_code}")
            
        except httpx.RequestError as exc_net:
            logger.error(f"Network error during tag deletion for '{image_name}:{tag_name}' by admin '{admin_user}': {exc_net}")
            log_entry_fail = AuditLogDBCreate(
                username=admin_user, action="IMAGE_TAG_DELETE_ATTEMPT", client_ip=client_ip,
                resource_type="image_tag", resource_name=f"{image_name}:{tag_name}", status="FAILURE",
                details={**action_details, "reason": f"Network error: {exc_net}", "manifest_digest_attempted": manifest_digest}
            )
            await log_audit_event(log_entry_fail)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="태그 삭제 중 네트워크 오류 발생.")
        except Exception as exc_other:
            logger.exception(f"Unexpected error during tag deletion for '{image_name}:{tag_name}' by admin '{admin_user}': {exc_other}")
            log_entry_fail = AuditLogDBCreate(
                username=admin_user, action="IMAGE_TAG_DELETE_ATTEMPT", client_ip=client_ip,
                resource_type="image_tag", resource_name=f"{image_name}:{tag_name}", status="FAILURE",
                details={**action_details, "reason": f"Unexpected error: {exc_other}", "manifest_digest_attempted": manifest_digest}
            )
            await log_audit_event(log_entry_fail)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="태그 삭제 중 예기치 않은 오류 발생.")
