from fastapi import FastAPI

app = FastAPI(title="My Private Docker Registry Service")

@app.get("/")
async def read_root():
    return {"message": "Welcome to My Private Docker Registry Service!"}

# Phase 1 목표 중 하나: Docker 클라이언트가 가장 먼저 호출하는 /v2/ 엔드포인트
# 우선은 간단히 응답만 하도록 만들어봅니다.
# 실제 Distribution Registry의 /v2/는 인증을 요구할 수 있고, 헤더를 통해 API 버전 지원 여부를 알립니다.
@app.get("/v2/")
async def check_v2_support():
    # 실제 Distribution Registry는 Docker-Distribution-API-Version 헤더를 포함하여 응답합니다.
    # response.headers["Docker-Distribution-API-Version"] = "registry/2.0"
    # 여기서는 우선 간단한 JSON 응답만 반환합니다.
    # 추후 실제 Distribution Registry의 /v2/로 요청을 프록시하도록 수정해야 합니다.
    return {}