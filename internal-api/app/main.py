
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from privacygate import gate_mode
from privacygate.web import assert_all_routes_guarded, install

from . import audit, db, jobs
from .config import get_settings
from .routers import auth, business, transfer, matching

logging.basicConfig(level=logging.INFO)


if gate_mode.is_baseline():
    logging.warning("GATE_MODE=baseline: 시연 비교 모드 (공격 ①② 대상 통제 꺼짐). 시연 후 enforce 로 되돌릴 것")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.open_pool(get_settings().database_url)
    jobs.start()
    yield
    jobs.stop()
    db.close_pool()



app = FastAPI(title="internal-api", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
install(app, audit.writer())

app.include_router(auth.router)
app.include_router(business.router)
app.include_router(transfer.router)
app.include_router(matching.router)


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}



assert_all_routes_guarded(app)
