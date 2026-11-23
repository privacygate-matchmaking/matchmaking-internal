"""사후 대응: 보안 사건 기록, 반복 거부 자동 임시 잠금, 잠금 확인.

- 직원이 역할 밖 경로를 60초 안에 3번 요청하면(role_not_allowed) 15분 동안 그 계정의 모든 요청을 막는다.
- 공격 ①(상담 직원의 관리자 전체 내보내기)은 첫 시도부터 보안 사건으로 남긴다. baseline 에서 통과한 경우도 '차단 안 됨'으로 남긴다.
- 공격 ②(회원의 승인 외 파일 요청)는 중계(transfer-api)가 알려 오면 보안 사건으로 남기고, 같은 회원이 60초 안에 3번 하면 잠근다.
- 일회용 다운로드 토큰 재사용·위조·생략(download_token_used/invalid/required)도 중계가 알려 오면 사건으로 남기고,
  같은 회원이 60초 안에 3번 하면 잠근다 (중계는 그 제공 건의 남은 토큰도 즉시 폐기한다).
- 사건에는 계정 id·직원/회원 코드·사유 코드만 넣는다 (이름·연락처·파일 내용 없음).
- 이 모듈의 실패는 차단 결정을 바꾸지 않는다 (호출하는 쪽에서 예외를 삼킨다).
"""
import logging
from datetime import datetime, timedelta, timezone

from fastapi import Request
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import STAFF_ROLES
from privacygate.web import route_action, trace_id

from . import audit, db, notify

_log = logging.getLogger("internal-api.security")

LOCK_THRESHOLD = 3                     # 같은 계정의 거부 신호 횟수
SIGNAL_WINDOW = timedelta(seconds=60)  # 세는 시간 범위 (Wazuh 100112 와 같은 기준)
LOCK_DURATION = timedelta(minutes=15)
MERGE_WINDOW = timedelta(minutes=10)   # 같은 계정·종류의 열린 사건이 이 시간 안이면 횟수만 늘린다
EXPORT_ACTION = "POST /api/admin/member-exports"
KST = timezone(timedelta(hours=9))

KIND_TITLE = {"unauthorized_export": "권한 밖 전체 회원 내보내기 시도",
              "approval_mismatch": "승인 외 자료 다운로드 시도",
              "repeated_denials": "역할 밖 요청 반복",
              "download_token_misuse": "일회용 다운로드 토큰 재사용·위조 시도"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def locked_until(conn, user_id) -> datetime | None:
    row = conn.execute("SELECT locked_until FROM account_locks WHERE user_id = %s AND locked_until > %s",
                       (str(user_id), _now())).fetchone()
    return row["locked_until"] if row else None


def lock_message(until: datetime) -> str:
    return (f"반복된 비정상 요청(권한 밖·승인 외 요청)으로 계정이 {until.astimezone(KST):%H:%M}까지 임시 잠겼습니다. "
            "정상 업무·이용 중이었다면 관리자(고객센터)에게 문의하세요.")


def ensure_not_locked(conn, user_id) -> None:
    until = locked_until(conn, user_id)
    if until:
        raise GateError(ErrorCode.ACCESS_DENIED, "account_temporarily_locked", lock_message(until))


def add_signal(conn, user_id, kind: str) -> int:
    """거부 신호를 남기고, 최근 SIGNAL_WINDOW 안 같은 종류 신호 수를 돌려준다."""
    now = _now()
    conn.execute("DELETE FROM security_signals WHERE user_id = %s AND created_at < %s",
                 (str(user_id), now - timedelta(days=1)))
    conn.execute("INSERT INTO security_signals (user_id, kind, created_at) VALUES (%s, %s, %s)",
                 (str(user_id), kind, now))
    row = conn.execute("SELECT count(*) AS n FROM security_signals WHERE user_id = %s AND kind = %s AND created_at > %s",
                       (str(user_id), kind, now - SIGNAL_WINDOW)).fetchone()
    return int(row["n"])


def lock(conn, user_id, reason: str) -> datetime | None:
    """잠금. 이미 잠겨 있으면 None (기간을 늘리지 않는다)."""
    if locked_until(conn, user_id):
        return None
    until = _now() + LOCK_DURATION
    conn.execute("""INSERT INTO account_locks (user_id, locked_until, reason, created_at) VALUES (%s, %s, %s, %s)
                    ON CONFLICT (user_id) DO UPDATE SET locked_until = EXCLUDED.locked_until,
                        reason = EXCLUDED.reason, created_at = EXCLUDED.created_at""",
                 (str(user_id), until, reason, _now()))
    return until


def record_incident(conn, *, kind: str, severity: str, subject: dict, source: str, detail: str,
                    trace: str | None, blocked: bool) -> tuple[str, bool]:
    """사건을 남긴다. 같은 계정·종류·차단 여부의 열린 사건이 최근에 있으면 횟수만 늘린다. → (incident_id, 새 사건인지)"""
    now = _now()
    row = conn.execute(
        """SELECT incident_id FROM security_incidents
            WHERE subject_user_id = %s AND kind = %s AND blocked = %s AND status IN ('new', 'reviewing')
              AND last_seen_at > %s ORDER BY last_seen_at DESC LIMIT 1""",
        (subject["user_id"], kind, blocked, now - MERGE_WINDOW)).fetchone()
    if row:
        conn.execute("""UPDATE security_incidents SET occurrences = occurrences + 1, last_seen_at = %s,
                               detail = %s, trace_id = %s WHERE incident_id = %s""",
                     (now, detail[:200], trace, row["incident_id"]))
        return str(row["incident_id"]), False
    row = conn.execute(
        """INSERT INTO security_incidents (kind, severity, subject_user_id, subject_code, subject_role, source,
                                           detail, trace_id, blocked, first_seen_at, last_seen_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING incident_id""",
        (kind, severity, subject["user_id"], subject.get("code"), subject.get("role"), source,
         detail[:200], trace, blocked, now, now)).fetchone()
    who = f"{subject.get('code') or '-'}({subject.get('role') or '-'})"
    notify.to_role(conn, "data_admin", "security_incident",
                   f"⚠ 보안 사건: {KIND_TITLE.get(kind, kind)}" + ("" if blocked else " (차단 안 됨)"),
                   f"{who} · {'차단됨' if blocked else '통과됨 — 즉시 확인'}", "security")
    return str(row["incident_id"]), True


def apply_lock(conn, request: Request, subject: dict, *, kind: str, source: str, reason: str) -> datetime | None:
    """임계값을 넘은 계정을 잠그고, 열린 사건에 잠금 시각을 붙인다 (없으면 '역할 밖 요청 반복' 사건을 만든다)."""
    until = lock(conn, subject["user_id"], reason)
    if until is None:
        return None
    row = conn.execute(
        """SELECT incident_id FROM security_incidents
            WHERE subject_user_id = %s AND status IN ('new', 'reviewing') AND last_seen_at > %s
            ORDER BY (kind = %s) DESC, last_seen_at DESC LIMIT 1""",
        (subject["user_id"], _now() - MERGE_WINDOW, kind)).fetchone()
    if row is None:
        incident_id, _ = record_incident(conn, kind="repeated_denials", severity="medium", subject=subject,
                                         source=source, detail=reason, trace=trace_id(request), blocked=True)
    else:
        incident_id = str(row["incident_id"])
    conn.execute("UPDATE security_incidents SET auto_locked_until = %s WHERE incident_id = %s", (until, incident_id))
    notify.to_role(conn, "data_admin", "security_incident", "🔒 계정 자동 임시 잠금",
                   f"{subject.get('code') or '-'}({subject.get('role') or '-'}) · {until.astimezone(KST):%H:%M}까지",
                   "security")
    audit.writer().record(trace_id=trace_id(request), action="security.auto_lock", result="allow",
                          actor="system", role=None, target_type="user", target_id=subject.get("code") or "-",
                          reason=reason)
    return until


def staff_subject(principal) -> dict:
    return {"user_id": principal.user_id, "code": principal.pseudo_id, "role": principal.role}


def on_deny(request: Request, exc: GateError) -> None:
    """privacygate.web.install 의 거부 훅. 직원의 역할 밖 요청만 센다."""
    principal = getattr(request.state, "principal", None)
    if exc.reason != "role_not_allowed" or principal is None or principal.role not in STAFF_ROLES:
        return
    action = route_action(request)
    subject = staff_subject(principal)
    with db.connection() as conn:
        if action == EXPORT_ACTION:
            record_incident(conn, kind="unauthorized_export", severity="high", subject=subject,
                            source="internal-api", detail=f"{action} · role_not_allowed",
                            trace=trace_id(request), blocked=True)
        if add_signal(conn, principal.user_id, "role_denied") >= LOCK_THRESHOLD:
            apply_lock(conn, request, subject, kind="unauthorized_export" if action == EXPORT_ACTION else "repeated_denials",
                       source="internal-api", reason="repeated_role_denials")
