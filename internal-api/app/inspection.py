"""증빙 자동 검사 연동 (doc-inspector).

1) 증빙 원본(암호문)을 복호화해 격리된 doc-inspector 로 보낸다 (inspect-net, 인터넷 없음).
2) 돌아온 결과 중 발급번호를 합성 발급대장(doc_registry)과 대조해 진위 판단(verified/suspicious/unchecked)을 정한다.
3) 추출 값(성명·생년월일·발급번호·금액 등)과 마스킹 사본은 암호화 저장소에만 두고, DB 에는 참/거짓 결과·건수만 남긴다.
"""
import base64
import hashlib
import json
import logging


import httpx

from . import audit, db, storage
from .config import get_settings

_log = logging.getLogger("internal-api.inspection")


class InspectionError(Exception):
    pass


def _call(data: bytes, kind: str) -> dict:
    s = get_settings()
    name, media = ("photo", "application/octet-stream") if kind == "photo" else ("evidence.pdf", "application/pdf")
    resp = httpx.post(f"{s.inspector_url}/inspect", data={"kind": kind}, files={"file": (name, data, media)}, timeout=90)
    if resp.status_code == 422:
        raise InspectionError(str(resp.json().get("detail", "unreadable"))[:120])
    if resp.status_code != 200:
        raise InspectionError(f"inspector_status_{resp.status_code}")
    return resp.json()


def _checks(conn, kind: str, result: dict, member) -> tuple[str, dict]:
    if kind == "photo":
        return "unchecked", {"metadata_removed": bool(result.get("photo", {}).get("metadata_removed"))}
    issue = result.get("issue") or {}
    checks = {"issue_format": bool(issue.get("format_ok")), "issue_checksum": bool(issue.get("checksum_ok")),
              "registry_found": False, "registry_kind": False, "name_match": False, "birth_match": False,
              "registry_revoked": False}
    fields = result.get("fields") or {}
    if issue.get("number"):
        reg = conn.execute("SELECT kind, holder_name, holder_birth, revoked FROM doc_registry WHERE issue_no = %s",
                           (issue["number"],)).fetchone()
        if reg:
            checks["registry_found"] = True
            checks["registry_kind"] = reg["kind"] == kind
            checks["registry_revoked"] = bool(reg["revoked"])
            checks["name_match"] = bool(fields.get("name")) and fields["name"] == reg["holder_name"] == member["name"]
            birth = fields.get("birth")
            checks["birth_match"] = bool(birth) and reg["holder_birth"] is not None and \
                birth == reg["holder_birth"].isoformat() and member["birth_date"] == reg["holder_birth"]
    if all(checks[k] for k in ("issue_format", "issue_checksum", "registry_found", "registry_kind", "name_match",
                               "birth_match")) and not checks["registry_revoked"]:
        verdict = "verified"
    elif not issue.get("number"):
        verdict = "unchecked"            # 발급번호를 읽지 못함 → 직원이 원본으로 판단
    else:
        verdict = "suspicious"           # 형식 오류·대장 없음·명의 불일치·폐기 문서
    return verdict, checks


def _drop_blobs(row) -> None:
    for key in (row.get("fields_key"), row.get("masked_key")):
        if key:
            try:
                storage.delete(key)
            except Exception:
                _log.exception("검사 파일 삭제 실패")


def run(file_id) -> dict:
    """증빙 한 건 검사. 이미 검사 결과가 있으면 지우고 다시 만든다."""
    with db.connection() as conn:
        ev = conn.execute("""SELECT e.file_id, e.kind, e.storage_key, e.status, m.name, m.birth_date
                               FROM evidence_files e JOIN members m ON m.member_id = e.member_id
                              WHERE e.file_id = %s""", (file_id,)).fetchone()
        old = conn.execute("SELECT fields_key, masked_key FROM evidence_inspections WHERE file_id = %s",
                           (file_id,)).fetchone()
    if ev is None or not ev["storage_key"] or ev["status"] not in ("submitted", "in_review"):
        raise InspectionError("evidence_not_open")
    version, verdict, checks, detected, proposed, summary = "doc-inspector", "unchecked", {}, {}, {}, None
    fields_key = masked_key = masked_hash = masked_type = error = None
    try:
        result = _call(storage.get(ev["storage_key"]), ev["kind"])
        version = str(result.get("version", "doc-inspector"))[:80]
        detected = {k: int(v) for k, v in (result.get("detected") or {}).items()}
        proposed = result.get("proposed") or {}
        summary = (result.get("summary") or None) and str(result["summary"])[:300]
        with db.connection() as conn:
            verdict, checks = _checks(conn, ev["kind"], result, ev)
        fields = {**(result.get("fields") or {}), "issue_no": (result.get("issue") or {}).get("number")}
        fields_key = f"inspect/{file_id}.fields"
        storage.put(fields_key, json.dumps(fields, ensure_ascii=False).encode("utf-8"))
        masked = result.get("masked") or {}
        if masked.get("data_base64") and masked.get("media_type") in ("image/png", "image/jpeg"):
            blob = base64.b64decode(masked["data_base64"], validate=True)
            masked_key, masked_type = f"inspect/{file_id}.masked", masked["media_type"]
            masked_hash = hashlib.sha256(blob).hexdigest()
            storage.put(masked_key, blob)
        status = "done"
    except (InspectionError, httpx.HTTPError, ValueError) as exc:
        status, error = "failed", str(exc)[:200] or exc.__class__.__name__
    with db.connection() as conn:
        conn.execute("DELETE FROM evidence_inspections WHERE file_id = %s", (file_id,))
        conn.execute(
            """INSERT INTO evidence_inspections (file_id, status, verdict, checks, detected, proposed, summary,
                                                 fields_key, masked_key, masked_hash, masked_type, error, version)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (file_id, status, verdict, json.dumps(checks), json.dumps(detected), json.dumps(proposed, ensure_ascii=False),
             summary, fields_key, masked_key, masked_hash, masked_type, error, version))
    if old:
        _drop_blobs(old)
    audit.writer().record(trace_id=hashlib.sha256(str(file_id).encode()).hexdigest()[:32], action="evidence_inspect",
                          result="allow" if status == "done" else "error", actor="system", target_type="evidence",
                          target_id=str(file_id), reason=verdict if status == "done" else (error or "failed")[:60])
    return {"status": status, "verdict": verdict}


def pending(limit: int = 5) -> int:
    """아직 검사하지 않은 열린 증빙을 처리 (주기 작업)."""
    with db.connection() as conn:
        rows = conn.execute("""SELECT e.file_id FROM evidence_files e
                                LEFT JOIN evidence_inspections i ON i.file_id = e.file_id
                               WHERE i.file_id IS NULL AND e.status IN ('submitted', 'in_review') AND e.storage_key IS NOT NULL
                               ORDER BY e.created_at LIMIT %s""", (limit,)).fetchall()
    done = 0
    for r in rows:
        try:
            run(r["file_id"])
            done += 1
        except InspectionError:
            continue
    return done


def drop_for_file(conn, file_id) -> None:
    """원본 삭제 때 검사 결과(추출 값·검사용 사본)도 함께 삭제."""
    row = conn.execute("DELETE FROM evidence_inspections WHERE file_id = %s RETURNING fields_key, masked_key",
                       (file_id,)).fetchone()
    if row:
        _drop_blobs(row)


