"""환경변수 설정. 비밀값은 코드에 두지 않는다."""
import os
from dataclasses import dataclass
from functools import lru_cache

SERVICE_NAME = "internal-api"
SESSION_COOKIE = "internal_session"


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"환경변수 {name} 가 필요합니다")
    return value


@dataclass(frozen=True)
class Settings:
    database_url: str
    oidc_discovery_url: str
    oidc_client_id: str              # Keycloak client: internal-web
    oidc_client_secret: str
    app_base_url: str                # 브라우저가 보는 내부 화면 주소
    api_audience: str                # 서버 간 호출 토큰의 aud (internal-api)
    transfer_api_url: str
    cookie_secure: bool
    session_idle_seconds: int
    session_max_seconds: int
    audit_log_path: str
    evidence_dir: str = "/data/evidence-storage"
    evidence_key_path: str = "/run/secrets/evidence_master_key"
    evidence_max_bytes: int = 2 * 1024 * 1024        # 회원 증빙 PDF 최대 2MiB (외부·중계 계약)
    evidence_retention_days: int = 7                 # 심사 후 원본 보관 기간
    evidence_unreviewed_days: int = 30               # 심사 전 원본 최대 보관 기간
    evidence_purge_seconds: int = 300                # 기한 삭제 작업 주기

    @property
    def redirect_uri(self) -> str:
        return f"{self.app_base_url}/auth/callback"


@lru_cache
def get_settings() -> Settings:
    return Settings(
        database_url=_required("DATABASE_URL"),
        oidc_discovery_url=_required("OIDC_DISCOVERY_URL"),
        oidc_client_id=os.environ.get("OIDC_CLIENT_ID", "internal-web"),
        oidc_client_secret=_required("OIDC_CLIENT_SECRET"),
        app_base_url=_required("APP_BASE_URL").rstrip("/"),
        api_audience=os.environ.get("API_AUDIENCE", "internal-api"),
        transfer_api_url=os.environ.get("TRANSFER_API_URL", "http://transfer-api:8000"),
        cookie_secure=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
        session_idle_seconds=int(os.environ.get("SESSION_IDLE_SECONDS", "1800")),
        session_max_seconds=int(os.environ.get("SESSION_MAX_SECONDS", "28800")),
        audit_log_path=os.environ.get("AUDIT_LOG_PATH", "/var/log/matchmaking/internal-api.json"),
        evidence_dir=os.environ.get("EVIDENCE_DIR", "/data/evidence-storage"),
        evidence_key_path=os.environ.get("EVIDENCE_KEY_PATH", "/run/secrets/evidence_master_key"),
        evidence_retention_days=int(os.environ.get("EVIDENCE_RETENTION_DAYS", "7")),
        evidence_unreviewed_days=int(os.environ.get("EVIDENCE_UNREVIEWED_DAYS", "30")),
        evidence_purge_seconds=int(os.environ.get("EVIDENCE_PURGE_SECONDS", "300")),
    )
