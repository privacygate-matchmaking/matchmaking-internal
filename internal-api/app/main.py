
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from privacygate import gate_mode, mtls_server
from privacygate.web import assert_all_routes_guarded, install

from . import audit, db, jobs, keycloak_events, security
from .config import get_settings
from .routers import auth, business, transfer, matching, signup, staff_signup, member_notify
from .routers import security as security_routes

logging.basicConfig(level=logging.INFO)


if gate_mode.is_baseline():
    logging.warning("GATE_MODE=baseline: 시연 비교 모드 (공격 ①② 대상 통제 꺼짐). 시연 후 enforce 로 되돌릴 것")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.open_pool(get_settings().database_url)
    jobs.start()
    keycloak_events.start()   # Keycloak 로그인 실패·역할 변경 → 감사 로그(→ Wazuh)
    yield
    jobs.stop()
    keycloak_events.stop()
    db.close_pool()



app = FastAPI(title="internal-api", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
install(app, audit.writer(), on_deny=security.on_deny)   # 거부 후 사후 대응 (반복 거부 잠금·사건 기록)
# mTLS 호출자 고정: MTLS_PEER_POLICY=internal-api 일 때 /api/internal/* 은 transfer-api 인증서만, 나머지는 internal-web 만
app.add_middleware(mtls_server.PeerGuard, on_deny=mtls_server.audit_hook(audit.writer()))

app.include_router(auth.router)
app.include_router(business.router)
app.include_router(transfer.router)
app.include_router(matching.router)
app.include_router(signup.router)
app.include_router(staff_signup.router)
app.include_router(member_notify.router)
app.include_router(security_routes.router)


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}



assert_all_routes_guarded(app)
