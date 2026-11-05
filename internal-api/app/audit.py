"""internal-api 감사 기록기: JSON 파일(→ Wazuh) + audit_log 테이블."""
from functools import lru_cache

from fastapi import Request
from privacygate.audit import AuditWriter
from privacygate.web import audit_request

from . import db
from .config import SERVICE_NAME, get_settings


def _insert(event: dict) -> None:
    with db.connection() as conn:
        conn.execute(
            """INSERT INTO audit_log
               (ts, trace_id, actor, role, action, target_type, target_id, result, reason)
               VALUES (%(ts)s, %(trace_id)s, %(actor)s, %(role)s, %(action)s,
                       %(target_type)s, %(target_id)s, %(result)s, %(reason)s)""",
            event,
        )


@lru_cache
def writer() -> AuditWriter:
    return AuditWriter(SERVICE_NAME, get_settings().audit_log_path, db_insert=_insert)


def allow(request: Request, *, action: str | None = None, target_type: str | None = None,
          target_id: str | None = None, reason: str | None = None) -> None:
    # baseline 모드에서 통제를 건너뛴 요청은 사유에 남긴다
    reason = reason or getattr(request.state, "gate_bypass", None)
    audit_request(writer(), request, "allow", action=action, target_type=target_type,
                  target_id=target_id, reason=reason)


def deny(request: Request, reason: str, *, action: str | None = None) -> None:
    audit_request(writer(), request, "deny", action=action, reason=reason)
