"""주기 작업: 증빙 원본 기한 삭제, 탈퇴 유예가 끝난 회원 삭제, 안내 기간이 끝난 회원 Keycloak 계정 삭제.

삭제 기한이 지난 증빙(법적 보존 legal_hold 제외)의 원본을 evidence-storage 에서 지우고 상태를 deleted 로 바꾼다.
성공·실패 모두 감사 로그에 action=evidence_delete 로 남긴다 (실패는 Wazuh 경보 대상).
"""
import logging
import threading
import uuid

from . import audit, db, keycloak_admin, notify, storage
from .config import get_settings

_log = logging.getLogger("internal-api.jobs")
_stop = threading.Event()


def purge_expired_evidence() -> int:
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT file_id, storage_key FROM evidence_files
                WHERE delete_after < now() AND status <> 'deleted' AND NOT legal_hold""").fetchall()
    done = 0
    for row in rows:
        trace = uuid.uuid4().hex
        try:
            if row["storage_key"]:
                storage.delete(row["storage_key"])
            with db.connection() as conn:
                conn.execute("UPDATE evidence_files SET status = 'deleted', storage_key = NULL WHERE file_id = %s",
                             (row["file_id"],))
            audit.writer().record(trace_id=trace, action="evidence_delete", result="allow", actor="system",
                                  target_type="evidence", target_id=str(row["file_id"]))
            done += 1
        except Exception:
            _log.exception("증빙 기한 삭제 실패")
            audit.writer().record(trace_id=trace, action="evidence_delete", result="error", actor="system",
                                  target_type="evidence", target_id=str(row["file_id"]),
                                  reason="delete_failed")
    return done


def purge_member(member_id) -> int:
    """회원과 관련 행을 DB 함수 purge_member 로 지우고, 그 회원의 증빙 암호문 파일도 지운다. 지운 파일 수를 돌려준다.
    (DB 삭제가 먼저 끝나야 파일을 지운다. 파일 삭제 실패는 감사 로그 error 로 남겨 Wazuh 가 경보)
    회원 로그인 계정이 있으면 DB 함수가 탈퇴 안내 기록을 남기고, 여기서 Keycloak 세션을 바로 끊는다.
    Keycloak 계정 자체는 안내 기간(MEMBER_NOTICE_DAYS) 뒤 delete_expired_accounts 가 지운다."""
    with db.connection() as conn:
        owner = conn.execute("SELECT user_id FROM members WHERE member_id = %s", (member_id,)).fetchone()
        keys = [r["storage_key"] for r in conn.execute("SELECT storage_key FROM purge_member(%s, %s)",
                                                         (member_id, get_settings().member_notice_days)).fetchall()]
    deleted = 0
    for key in keys:
        try:
            storage.delete(key)
            deleted += 1
        except Exception:
            _log.exception("탈퇴 회원 증빙 파일 삭제 실패")
            audit.writer().record(trace_id=uuid.uuid4().hex, action="evidence_delete", result="error",
                                  actor="system", target_type="evidence", target_id=key, reason="delete_failed")
    if owner and owner["user_id"]:
        if get_settings().member_notice_days <= 0:
            delete_member_account(str(owner["user_id"]))      # 안내 기간 0 이면 바로 계정 삭제
        elif keycloak_admin.enabled():
            try:
                keycloak_admin.logout(str(owner["user_id"]))
            except Exception:
                _log.exception("탈퇴 회원 Keycloak 세션 종료 실패")
    return deleted


def delete_member_account(user_id: str) -> bool:
    """회원 Keycloak 계정을 지우고 안내 기록도 지운다. 실패하면 기록을 남겨 다음 주기에 다시 시도한다."""
    trace = uuid.uuid4().hex
    if not keycloak_admin.enabled():
        _log.warning("KC_ADMIN_CLIENT_SECRET 이 없어 회원 Keycloak 계정을 지우지 못했습니다")
        return False
    try:
        result = keycloak_admin.delete_member(user_id)
    except keycloak_admin.KeycloakAdminError as e:
        audit.writer().record(trace_id=trace, action="member_account_delete", result="error", actor="system",
                              target_type="keycloak_user", target_id=user_id, reason=str(e))
        return False
    except Exception:
        _log.exception("회원 Keycloak 계정 삭제 실패")
        audit.writer().record(trace_id=trace, action="member_account_delete", result="error", actor="system",
                              target_type="keycloak_user", target_id=user_id, reason="keycloak_unavailable")
        return False
    with db.connection() as conn:
        conn.execute("DELETE FROM withdrawal_notices WHERE user_id = %s", (user_id,))
    audit.writer().record(trace_id=trace, action="member_account_delete", result="allow", actor="system",
                          target_type="keycloak_user", target_id=user_id, reason=result)
    return True


def delete_expired_accounts() -> int:
    """안내 기간이 끝난 탈퇴 회원의 Keycloak 계정 삭제."""
    with db.connection() as conn:
        rows = conn.execute("SELECT user_id FROM withdrawal_notices WHERE account_delete_after <= now()").fetchall()
    return sum(1 for r in rows if delete_member_account(str(r["user_id"])))


def purge_due_members() -> int:
    """탈퇴 유예(7일)가 끝난 회원을 삭제한다."""
    with db.connection() as conn:
        rows = conn.execute("""SELECT member_id, pseudo_id FROM members
                                WHERE status = 'withdraw_pending' AND withdraw_at <= now()""").fetchall()
    for row in rows:
        trace = uuid.uuid4().hex
        try:
            with db.connection() as conn:
                text = f"{notify.member_label(conn, row['member_id'])} 회원의 탈퇴 유예가 끝나 회원 정보를 삭제했습니다."
                notify.to_counselors_of(conn, row["member_id"], "member_deleted", "탈퇴 확정", text, "manage")
                notify.to_role(conn, "data_admin", "member_deleted", "탈퇴 확정", text, "manage")
            purge_member(row["member_id"])
            audit.writer().record(trace_id=trace, action="member_purge", result="allow", actor="system",
                                  target_type="member", target_id=row["pseudo_id"])
        except Exception:
            _log.exception("탈퇴 회원 삭제 실패")
            audit.writer().record(trace_id=trace, action="member_purge", result="error", actor="system",
                                  target_type="member", target_id=row["pseudo_id"], reason="purge_failed")
    return len(rows)


def _loop() -> None:
    interval = get_settings().evidence_purge_seconds
    while not _stop.wait(interval):
        try:
            purge_expired_evidence()
        except Exception:
            _log.exception("기한 삭제 작업 오류")
        try:
            purge_due_members()
        except Exception:
            _log.exception("탈퇴 회원 삭제 작업 오류")
        try:
            delete_expired_accounts()
        except Exception:
            _log.exception("탈퇴 회원 Keycloak 계정 삭제 작업 오류")


def start() -> threading.Thread:
    _stop.clear()
    t = threading.Thread(target=_loop, name="evidence-purge", daemon=True)
    t.start()
    return t


def stop() -> None:
    _stop.set()
