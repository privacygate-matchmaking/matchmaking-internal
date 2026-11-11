"""matchmaking-internal / internal-api 진입점."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from privacygate import gate_mode
from privacygate.web import assert_all_routes_guarded, install

from . import audit, db, jobs
from .config import get_settings
from .routers import auth, business, transfer

logging.basicConfig(level=logging.INFO)

# GATE_MODE 값이 잘못되면 여기서 시작을 멈춘다
if gate_mode.is_baseline():
    logging.warning("GATE_MODE=baseline: 시연 비교 모드 (공격 ①② 대상 통제 꺼짐). 시연 후 enforce 로 되돌릴 것")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.open_pool(get_settings().database_url)
    jobs.start()                      # 증빙 기한 삭제 주기 작업
    yield
    jobs.stop()
    db.close_pool()


# 문서 화면(/docs)은 공격 표면이 되므로 끈다
app = FastAPI(title="internal-api", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
install(app, audit.writer())          # trace_id, 공통 오류 응답, 거부 감사 기록

app.include_router(auth.router)
app.include_router(business.router)
app.include_router(transfer.router)


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


# 기본 거부: 권한 선언 없는 /api 경로가 있으면 시작하지 않는다
assert_all_routes_guarded(app)
