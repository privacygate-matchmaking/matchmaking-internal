"""주기 작업: 증빙 원본 기한 삭제.

삭제 기한이 지난 증빙(법적 보존 legal_hold 제외)의 원본을 evidence-storage 에서 지우고 상태를 deleted 로 바꾼다.
성공·실패 모두 감사 로그에 action=evidence_delete 로 남긴다 (실패는 Wazuh 경보 대상).
"""
import logging
import threading
import uuid

from . import audit, db, storage
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


def _loop() -> None:
    interval = get_settings().evidence_purge_seconds
    while not _stop.wait(interval):
        try:
            purge_expired_evidence()
        except Exception:
            _log.exception("기한 삭제 작업 오류")


def start() -> threading.Thread:
    _stop.clear()
    t = threading.Thread(target=_loop, name="evidence-purge", daemon=True)
    t.start()
    return t


def stop() -> None:
    _stop.set()
