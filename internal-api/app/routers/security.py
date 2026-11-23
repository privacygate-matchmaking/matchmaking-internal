"""보안 사건 대응 (총관리자 화면) + 중계가 보내는 보안 사건 접수.

- 총관리자: 사건 목록·상세, 검토 상태(신규/검토 중/조치 완료/오탐)·메모, 조치(계정 정지·복구, 임시 잠금 해제, 받은 자료 회수).
- 계정 정지: 업무 DB users.active=false(함수 set_account_active, 직원 세션 삭제) + Keycloak 비활성·세션 종료.
  총관리자 본인·다른 총관리자는 정지할 수 없다.
- 받은 자료 회수: 회원이 받은 소개 자료 승인을 중계에서 모두 회수한다 (총관리자 토큰으로 중계 호출).
- 모든 조치는 감사 로그(action=security.*)와 사건 조치 기록에 남는다.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, Request
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import Principal, Role
from privacygate.web import trace_id
from pydantic import BaseModel, Field

from .. import audit, db, keycloak_admin, security, transfer_client
from ..auth.session import member_token_via_transfer, require, require_csrf

router = APIRouter(prefix="/api", tags=["security"])
_log = logging.getLogger("internal-api.security")

STATUSES = ("new", "reviewing", "resolved", "false_positive")
OPEN = ("new", "reviewing")


def _iso(value) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def _subject_state(conn, user_id) -> dict:
    if not user_id:
        return {"exists": False, "active": None, "locked_until": None}
    row = conn.execute("SELECT active FROM users WHERE user_id = %s", (str(user_id),)).fetchone()
    return {"exists": row is not None, "active": bool(row["active"]) if row else None,
            "locked_until": _iso(security.locked_until(conn, user_id))}


def _item(r, state: dict) -> dict:
    return {"incident_id": str(r["incident_id"]), "kind": r["kind"], "title": security.KIND_TITLE.get(r["kind"], r["kind"]),
            "severity": r["severity"], "subject_user_id": str(r["subject_user_id"]) if r["subject_user_id"] else None,
            "subject_code": r["subject_code"], "subject_role": r["subject_role"], "source": r["source"],
            "detail": r["detail"], "trace_id": r["trace_id"], "blocked": r["blocked"], "occurrences": r["occurrences"],
            "auto_locked_until": _iso(r["auto_locked_until"]), "status": r["status"], "note": r["note"],
            "first_seen_at": _iso(r["first_seen_at"]), "last_seen_at": _iso(r["last_seen_at"]),
            "updated_at": _iso(r["updated_at"]), "subject": state}


def _incident(conn, incident_id, lock: bool = False):
    row = conn.execute("SELECT * FROM security_incidents WHERE incident_id = %s" + (" FOR UPDATE" if lock else ""),
                       (str(incident_id),)).fetchone()
    if row is None:
        raise GateError(ErrorCode.NOT_FOUND, "incident_missing")
    return row


@router.get("/admin/security-incidents")
def list_incidents(request: Request, status: Literal["open", "all"] = "open",
                   principal: Principal = Depends(require(Role.DATA_ADMIN))):
    with db.connection() as conn:
        where = "WHERE status IN ('new', 'reviewing')" if status == "open" else ""
        rows = conn.execute(f"SELECT * FROM security_incidents {where} ORDER BY last_seen_at DESC LIMIT 200").fetchall()
        items = [_item(r, _subject_state(conn, r["subject_user_id"])) for r in rows]
        counts = conn.execute("SELECT status, count(*) AS n FROM security_incidents GROUP BY status").fetchall()
    audit.allow(request, target_type="security_incident_list")
    return {"items": items, "counts": {c["status"]: c["n"] for c in counts}}


@router.get("/admin/security-incidents/{incident_id}")
def get_incident(incident_id: uuid.UUID, request: Request, principal: Principal = Depends(require(Role.DATA_ADMIN))):
    with db.connection() as conn:
        r = _incident(conn, incident_id)
        actions = conn.execute(
            """SELECT a.action, a.result, a.detail, a.created_at, u.pseudo_id
                 FROM incident_actions a JOIN users u ON u.user_id = a.actor_id
                WHERE a.incident_id = %s ORDER BY a.created_at""", (str(incident_id),)).fetchall()
        item = _item(r, _subject_state(conn, r["subject_user_id"]))
    audit.allow(request, target_type="security_incident", target_id=str(incident_id))
    item["actions"] = [{"action": a["action"], "result": a["result"], "detail": a["detail"], "actor": a["pseudo_id"],
                        "created_at": _iso(a["created_at"])} for a in actions]
    return item


class StatusIn(BaseModel):
    status: Literal["new", "reviewing", "resolved", "false_positive"]
    note: str | None = Field(default=None, max_length=500)


@router.post("/admin/security-incidents/{incident_id}/status")
def set_status(incident_id: uuid.UUID, body: StatusIn, request: Request,
               principal: Principal = Depends(require(Role.DATA_ADMIN)), _csrf: None = Depends(require_csrf)):
    note = (body.note or "").strip() or None
    with db.connection() as conn:
        r = _incident(conn, incident_id, lock=True)
        conn.execute("""UPDATE security_incidents SET status = %s, note = COALESCE(%s, note), updated_by = %s,
                               updated_at = now() WHERE incident_id = %s""",
                     (body.status, note, principal.user_id, str(incident_id)))
        conn.execute("INSERT INTO incident_actions (incident_id, actor_id, action, result, detail) VALUES (%s, %s, 'status', %s, %s)",
                     (str(incident_id), principal.user_id, f"{r['status']}->{body.status}", note))
    audit.allow(request, action="security.incident_status", target_type="security_incident",
                target_id=str(incident_id), reason=body.status)
    return {"incident_id": str(incident_id), "status": body.status}


class ActionIn(BaseModel):
    action: Literal["suspend_account", "restore_account", "unlock", "revoke_deliveries"]
    note: str | None = Field(default=None, max_length=500)


def _keycloak(user_id: str, enabled: bool) -> str:
    """Keycloak 반영 결과 코드. 관리 연결이 없거나 실패해도 업무 DB 정지는 유지한다 (업무 API 는 users.active 로 막힌다)."""
    if not keycloak_admin.enabled():
        return "keycloak_not_configured"
    try:
        return "keycloak_" + keycloak_admin.set_account_enabled(user_id, enabled)
    except (keycloak_admin.KeycloakAdminError, httpx.HTTPError) as exc:
        _log.warning("Keycloak 계정 상태 변경 실패: %s", getattr(exc, "args", [""])[0] if exc.args else type(exc).__name__)
        return "keycloak_failed"


@router.post("/admin/security-incidents/{incident_id}/actions")
def incident_action(incident_id: uuid.UUID, body: ActionIn, request: Request,
                    principal: Principal = Depends(require(Role.DATA_ADMIN)), _csrf: None = Depends(require_csrf)):
    note = (body.note or "").strip() or None
    with db.connection() as conn:
        r = _incident(conn, incident_id)
    subject = str(r["subject_user_id"]) if r["subject_user_id"] else None
    if not subject:
        raise GateError(ErrorCode.INVALID_STATE, "incident_without_subject", "대상 계정이 없는 사건입니다.")
    result: dict = {"incident_id": str(incident_id), "action": body.action}

    if body.action in ("suspend_account", "restore_account"):
        active = body.action == "restore_account"
        with db.connection() as conn:
            try:
                role = conn.execute("SELECT set_account_active(%s, %s, %s) AS role",
                                    (subject, active, principal.user_id)).fetchone()["role"]
            except Exception as exc:   # 함수가 거부(본인·총관리자·없는 계정): 사유는 로그에만
                conn.rollback()
                _log.info("set_account_active 거부: %s", type(exc).__name__)
                raise GateError(ErrorCode.INVALID_STATE, "account_change_refused",
                                "이 계정은 정지·복구할 수 없습니다 (본인·총관리자·없는 계정).") from None
        code = _keycloak(subject, active)
        result.update(subject_role=role, keycloak=code, active=active)
        outcome = code
    elif body.action == "unlock":
        with db.connection() as conn:
            n = conn.execute("DELETE FROM account_locks WHERE user_id = %s", (subject,)).rowcount
        result.update(unlocked=bool(n))
        outcome = "unlocked" if n else "not_locked"
    else:  # revoke_deliveries
        if r["subject_role"] != "member":
            raise GateError(ErrorCode.INVALID_STATE, "not_member_subject", "회원이 대상인 사건에서만 자료를 회수할 수 있습니다.")
        resp = transfer_client.call(request, "POST", f"/api/security/recipients/{subject}/revoke-deliveries", json={})
        if resp.status_code != 200:
            audit.deny(request, f"transfer_status_{resp.status_code}", action="security.revoke_deliveries")
            return transfer_client.relay(resp)
        revoked = int(resp.json().get("revoked", 0))
        result.update(revoked=revoked)
        outcome = f"revoked_{revoked}"

    with db.connection() as conn:
        conn.execute("INSERT INTO incident_actions (incident_id, actor_id, action, result, detail) VALUES (%s, %s, %s, %s, %s)",
                     (str(incident_id), principal.user_id, body.action, outcome[:64], note))
        if r["status"] == "new":
            conn.execute("UPDATE security_incidents SET status = 'reviewing', updated_by = %s, updated_at = now() "
                         "WHERE incident_id = %s AND status = 'new'", (principal.user_id, str(incident_id)))
    audit.allow(request, action=f"security.{body.action}", target_type="user",
                target_id=r["subject_code"] or "-", reason=outcome[:64])
    return result


# ---------------------------------------------------------------------------
# 중계(transfer-api) → 내부: 회원의 승인 외 자료 요청·다운로드 토큰 오용 알림.
# 대상은 본문이 아니라 검증된 회원 토큰(X-User-Token)으로 정한다.
# ---------------------------------------------------------------------------
class SecurityEventIn(BaseModel):
    kind: Literal["approval_mismatch", "download_token_misuse"]
    reason: str = Field(pattern=r"^[a-z_]{1,64}$")
    blocked: bool
    delivery_id: uuid.UUID | None = None


@router.post("/internal/security-events")
def security_event(body: SecurityEventIn, request: Request, sub: str = Depends(member_token_via_transfer)):
    with db.connection() as conn:
        row = conn.execute("SELECT user_id, pseudo_id, role FROM users WHERE user_id = %s", (sub,)).fetchone()
        subject = {"user_id": sub, "code": row["pseudo_id"] if row else None, "role": row["role"] if row else "member"}
        detail = body.reason + (f" · delivery {str(body.delivery_id)[:8]}" if body.delivery_id else "")
        # 토큰 생략(download_token_required)은 화면을 거치지 않은 직접 호출 의심이라 중간, 재사용·위조는 높음
        severity = "medium" if body.reason == "download_token_required" else "high"
        incident_id, _ = security.record_incident(conn, kind=body.kind, severity=severity, subject=subject,
                                                  source="transfer-api", detail=detail, trace=trace_id(request),
                                                  blocked=body.blocked)
        until = None
        if body.blocked and security.add_signal(conn, sub, body.kind) >= security.LOCK_THRESHOLD:
            until = security.apply_lock(conn, request, subject, kind=body.kind, source="transfer-api",
                                        reason=f"repeated_{body.kind}")
        locked = security.locked_until(conn, sub)
    audit.allow(request, action="security.incident", target_type="security_incident", target_id=incident_id,
                reason=body.reason)
    return {"incident_id": incident_id, "locked_until": _iso(locked), "newly_locked": until is not None}
