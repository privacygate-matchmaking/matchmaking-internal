"""내부 업무 API (docs/api-spec.md 의 '내부').

원칙
- 권한 검사(역할·담당·배정·소유)는 자료를 읽거나 파일을 만들기 전에 끝낸다.
- 담당이 아닌 회원·배정되지 않은 증빙은 404 로 답해 존재 자체를 알리지 않는다.
- 응답 본문에는 판단 근거를 넣지 않고 감사 로그에만 남긴다.
- 회원 본인 기능은 transfer-api 서비스 토큰 + 회원 토큰을 검증하고, 회원은 토큰 sub 로만 정한다.
"""
import csv
import io
import uuid
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import Response
from privacygate import gate_mode
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import STAFF_ROLES, Principal, Role
from pydantic import BaseModel, Field

from .. import audit, db, storage, transfer_client
from ..auth.session import member_via_transfer, require, require_csrf, require_service
from ..config import get_settings

router = APIRouter(prefix="/api", tags=["business"])

CONSENT_ITEMS = ("profile", "photo", "contact")
MAX_CONSENT_DAYS = 365


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _member_of(user_id: str) -> dict:
    """회원 토큰 sub → 회원 행. 업무 DB 에 없는 회원이면 거부."""
    with db.connection() as conn:
        row = conn.execute("SELECT member_id, pseudo_id FROM members WHERE user_id = %s",
                           (user_id,)).fetchone()
    if row is None:
        raise GateError(ErrorCode.ACCESS_DENIED, "member_record_missing")
    return row


@router.get("/me")
def me(request: Request, principal: Principal = Depends(require(*STAFF_ROLES))):
    """화면 표시용. 역할은 서버가 매 요청 확인하므로 화면은 이 값을 표시에만 쓴다."""
    return {"user_id": principal.user_id, "pseudo_id": principal.pseudo_id, "role": principal.role,
            "csrf_token": request.state.csrf_token,
            "gate_mode": gate_mode.current()}      # baseline 이면 화면 상단에 경고 표시


# ======================================================================
# 회원 (counselor)
# ======================================================================
@router.get("/members")
def list_members(request: Request, principal: Principal = Depends(require(Role.COUNSELOR))):
    """담당 관계가 있는 회원의 허용 항목만 (가명 ID·출생연도·직업). 이름·연락처는 주지 않는다."""
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT m.member_id, m.pseudo_id, m.birth_year, m.job
                 FROM assignments a JOIN members m ON m.member_id = a.member_id
                WHERE a.user_id = %s ORDER BY m.pseudo_id""",
            (principal.user_id,)).fetchall()
    audit.allow(request, target_type="member_list")
    return {"items": [{"member_id": str(r["member_id"]), "pseudo_id": r["pseudo_id"],
                       "birth_year": r["birth_year"], "job": r["job"]} for r in rows]}


@router.get("/members/{member_id}")
def get_member(member_id: uuid.UUID, request: Request,
               principal: Principal = Depends(require(Role.COUNSELOR))):
    """담당 회원 상세: 허용 항목 + 이 회원이 정보 주체인 유효 동의 (반출 신청에 필요한 ID 포함).
    담당이 아니면 404."""
    with db.connection() as conn:
        m = conn.execute(
            """SELECT m.member_id, m.pseudo_id, m.birth_year, m.job
                 FROM assignments a JOIN members m ON m.member_id = a.member_id
                WHERE a.user_id = %s AND m.member_id = %s""",
            (principal.user_id, member_id)).fetchone()
        if m is None:
            raise GateError(ErrorCode.NOT_FOUND, "member_not_assigned")
        consents = conn.execute(
            """SELECT c.consent_id, c.item, c.purpose, c.expires_at, c.revoked_at,
                      cm.pseudo_id AS counterpart_pseudo_id, cm.user_id AS recipient_id
                 FROM consents c JOIN members cm ON cm.member_id = c.counterpart_member_id
                WHERE c.member_id = %s ORDER BY c.granted_at DESC""",
            (member_id,)).fetchall()
    audit.allow(request, target_type="member", target_id=m["pseudo_id"])
    return {"member_id": str(m["member_id"]), "pseudo_id": m["pseudo_id"],
            "birth_year": m["birth_year"], "job": m["job"],
            "consents": [{"consent_id": str(c["consent_id"]), "item": c["item"], "purpose": c["purpose"],
                          "counterpart_pseudo_id": c["counterpart_pseudo_id"],
                          "recipient_id": str(c["recipient_id"]) if c["recipient_id"] else None,
                          "expires_at": _iso(c["expires_at"]), "revoked_at": _iso(c["revoked_at"]),
                          "valid": c["revoked_at"] is None and c["expires_at"] > _now()}
                         for c in consents]}


# ======================================================================
# 관리자 전체 회원 내보내기 (공격 ① 대상)
# ======================================================================
EXPORT_COLUMNS = ("pseudo_id", "name", "birth_year", "job", "contact_phone", "contact_email")


@router.post("/admin/member-exports", status_code=201)
def create_member_export(request: Request,
                         principal: Principal = Depends(require(Role.DATA_ADMIN, baseline_open=True)),
                         _csrf: None = Depends(require_csrf)):
    """전체 회원 CSV 를 만들어 암호화 저장하고 export_id 와 건수만 응답한다 (내려받기 경로 없음).
    GATE_MODE=baseline 이면 역할 검사를 건너뛴다 (공격 ① 비교 시연용)."""
    with db.connection() as conn:
        rows = conn.execute(f"SELECT {', '.join(EXPORT_COLUMNS)} FROM members ORDER BY pseudo_id").fetchall()
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=EXPORT_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    data = buf.getvalue().encode("utf-8")

    export_id = uuid.uuid4()
    key = f"exports/{export_id}.bin"
    storage.put(key, data)
    with db.connection() as conn:
        row = conn.execute(
            """INSERT INTO member_exports (export_id, created_by, row_count, storage_key, file_hash)
               VALUES (%s, %s, %s, %s, %s) RETURNING created_at""",
            (export_id, principal.user_id, len(rows), key, storage.sha256_hex(data))).fetchone()
    audit.allow(request, target_type="member_export", target_id=str(export_id))
    return {"export_id": str(export_id), "row_count": len(rows), "created_at": _iso(row["created_at"])}


@router.get("/admin/members")
def admin_list_members(request: Request, principal: Principal = Depends(require(Role.DATA_ADMIN))):
    """총관리자(data_admin) 회원 관리 목록: 전체 회원의 허용 항목 + 담당 직원. 이름·연락처는 주지 않는다. ※ 명세 외 추가"""
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT m.member_id, m.pseudo_id, m.birth_year, m.job, m.created_at,
                      (m.user_id IS NOT NULL) AS has_account,
                      (SELECT string_agg(u.pseudo_id || ' ' || u.display_name, ', ' ORDER BY u.pseudo_id)
                         FROM assignments a JOIN users u ON u.user_id = a.user_id
                        WHERE a.member_id = m.member_id) AS counselors,
                      (SELECT count(*) FROM consents c
                        WHERE c.member_id = m.member_id AND c.revoked_at IS NULL AND c.expires_at > now()) AS valid_consents
                 FROM members m ORDER BY m.pseudo_id""").fetchall()
    audit.allow(request, target_type="member_list_all")
    return {"items": [{"member_id": str(r["member_id"]), "pseudo_id": r["pseudo_id"],
                       "birth_year": r["birth_year"], "job": r["job"], "has_account": r["has_account"],
                       "counselors": r["counselors"], "valid_consents": r["valid_consents"],
                       "created_at": _iso(r["created_at"])} for r in rows]}


@router.get("/admin/member-exports")
def admin_list_exports(request: Request, principal: Principal = Depends(require(Role.DATA_ADMIN))):
    """전체 회원 내보내기 내역 (파일 내용 없음). 이상 내보내기 확인용. ※ 명세 외 추가"""
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT e.export_id, u.pseudo_id, u.role, e.row_count, e.transfer_file_id, e.created_at
                 FROM member_exports e JOIN users u ON u.user_id = e.created_by
                ORDER BY e.created_at DESC LIMIT 50""").fetchall()
    audit.allow(request, target_type="member_export_list")
    return {"items": [{"export_id": str(r["export_id"]), "created_by": r["pseudo_id"], "created_by_role": r["role"],
                       "row_count": r["row_count"],
                       "transfer_file_id": str(r["transfer_file_id"]) if r["transfer_file_id"] else None,
                       "created_at": _iso(r["created_at"])} for r in rows]}


@router.post("/member-exports/{export_id}/transfer-files", status_code=201)
def register_export_to_transfer(export_id: uuid.UUID, request: Request,
                                principal: Principal = Depends(require(Role.COUNSELOR)),
                                _csrf: None = Depends(require_csrf)):
    """내보내기 결과를 중계 반출 대기 영역에 등록한다 (공격 연결 단계). ※ 명세 외 추가
    본인이 만든 내보내기만. enforce 에서는 counselor 가 내보내기를 만들 수 없으므로 대상이 없다.
    파일 바이트를 multipart 로 transfer-api POST /api/transfer-files 에 보낸다 (CSV 는 중계에서 blocked)."""
    with db.connection() as conn:
        row = conn.execute("SELECT storage_key, transfer_file_id FROM member_exports "
                           "WHERE export_id = %s AND created_by = %s",
                           (export_id, principal.user_id)).fetchone()
    if row is None:
        raise GateError(ErrorCode.NOT_FOUND, "export_not_owned")
    if row["transfer_file_id"]:
        raise GateError(ErrorCode.INVALID_STATE, "export_already_registered")
    data = storage.get(row["storage_key"])
    resp = transfer_client.call(request, "POST", "/api/transfer-files",
                                files={"file": (f"member-export-{export_id}.csv", data, "text/csv")})
    if resp.status_code == 201:
        body = resp.json()
        with db.connection() as conn:
            conn.execute("UPDATE member_exports SET transfer_file_id = %s WHERE export_id = %s",
                         (body.get("file_id"), export_id))
        audit.allow(request, target_type="member_export", target_id=str(export_id))
    else:
        audit.deny(request, f"transfer_status_{resp.status_code}")
    return transfer_client.relay(resp)


# ======================================================================
# 증빙 (회원 제출 → data_admin 심사)
# ======================================================================
def _assign_reviewer(conn) -> str:
    row = conn.execute(
        """SELECT u.user_id FROM users u
             LEFT JOIN evidence_files e ON e.reviewer_user_id = u.user_id
                                       AND e.status IN ('submitted', 'in_review')
            WHERE u.role = 'data_admin' AND u.active
            GROUP BY u.user_id ORDER BY count(e.file_id), u.user_id LIMIT 1""").fetchone()
    if row is None:
        raise GateError(ErrorCode.INVALID_STATE, "no_reviewer")
    return row["user_id"]


@router.post("/evidence-files", status_code=201)
async def submit_evidence(request: Request, file: UploadFile = File(...),
                          member: Principal = Depends(member_via_transfer)):
    """회원 증빙 제출 (회원 → external-api → transfer-api → 여기). PDF, 최대 2MiB.
    본인(토큰 sub 의 회원) 명의로만 접수하고 AES-GCM 으로 암호화해 저장한다."""
    s = get_settings()
    data = await file.read(s.evidence_max_bytes + 1)
    if len(data) > s.evidence_max_bytes:
        raise GateError(ErrorCode.INVALID_REQUEST, "evidence_too_large")
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
        raise GateError(ErrorCode.INVALID_REQUEST, "evidence_not_pdf")
    owner = _member_of(member.user_id)
    file_id = uuid.uuid4()
    key = f"evidence/{file_id}.bin"
    storage.put(key, data)
    with db.connection() as conn:
        reviewer = _assign_reviewer(conn)
        row = conn.execute(
            """INSERT INTO evidence_files (file_id, member_id, submitted_by, reviewer_user_id, storage_key,
                                           key_id, file_hash, status, delete_after)
               VALUES (%s, %s, %s, %s, %s, %s, %s, 'submitted', %s) RETURNING created_at""",
            (file_id, owner["member_id"], member.user_id, reviewer, key, storage.key_id(),
             storage.sha256_hex(data), _now() + timedelta(days=s.evidence_unreviewed_days))).fetchone()
    audit.allow(request, target_type="evidence", target_id=str(file_id))
    return {"file_id": str(file_id), "status": "submitted", "created_at": _iso(row["created_at"])}


@router.get("/evidence-files")
def list_evidence(request: Request, principal: Principal = Depends(require(Role.DATA_ADMIN))):
    """나에게 배정된 증빙 목록만. 원본 내용은 넣지 않는다. ※ 명세 외 추가"""
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT e.file_id, m.pseudo_id, e.status, e.created_at, e.delete_after, e.legal_hold,
                      r.result
                 FROM evidence_files e JOIN members m ON m.member_id = e.member_id
                 LEFT JOIN evidence_reviews r ON r.file_id = e.file_id
                WHERE e.reviewer_user_id = %s ORDER BY e.created_at DESC""",
            (principal.user_id,)).fetchall()
    audit.allow(request, target_type="evidence_list")
    return {"items": [{"file_id": str(r["file_id"]), "member_pseudo_id": r["pseudo_id"],
                       "status": r["status"], "review_result": r["result"],
                       "created_at": _iso(r["created_at"]), "delete_after": _iso(r["delete_after"]),
                       "legal_hold": r["legal_hold"]} for r in rows]}


def _assigned_evidence(conn, file_id, user_id) -> dict:
    row = conn.execute("SELECT file_id, storage_key, status FROM evidence_files "
                       "WHERE file_id = %s AND reviewer_user_id = %s", (file_id, user_id)).fetchone()
    if row is None:
        raise GateError(ErrorCode.NOT_FOUND, "evidence_not_assigned")
    return row


@router.get("/evidence-files/{file_id}/content")
def read_evidence(file_id: uuid.UUID, request: Request,
                  principal: Principal = Depends(require(Role.DATA_ADMIN))):
    """배정된 데이터 관리자만, 심사 중(submitted·in_review)에만 복호화해 보여 준다.
    처음 열면 상태가 in_review 로 바뀐다. 브라우저 저장·캐시를 막는 헤더를 붙인다."""
    with db.connection() as conn:
        row = _assigned_evidence(conn, file_id, principal.user_id)
        if row["status"] not in ("submitted", "in_review") or not row["storage_key"]:
            raise GateError(ErrorCode.INVALID_STATE, f"evidence_{row['status']}")
        if row["status"] == "submitted":
            conn.execute("UPDATE evidence_files SET status = 'in_review' WHERE file_id = %s", (file_id,))
    data = storage.get(row["storage_key"])
    audit.allow(request, target_type="evidence", target_id=str(file_id))
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": "inline", "Cache-Control": "no-store",
                             "X-Content-Type-Options": "nosniff",
                             "Content-Security-Policy": "sandbox; default-src 'none'"})


class ReviewIn(BaseModel):
    result: str = Field(pattern="^(passed|rejected)$")


@router.post("/evidence-files/{file_id}/review")
def review_evidence(file_id: uuid.UUID, body: ReviewIn, request: Request,
                    principal: Principal = Depends(require(Role.DATA_ADMIN)),
                    _csrf: None = Depends(require_csrf)):
    """심사 결과 저장 → 상태 reviewed, 원본 삭제 기한 = 지금 + 보관 기간."""
    s = get_settings()
    delete_after = _now() + timedelta(days=s.evidence_retention_days)
    with db.connection() as conn:
        row = _assigned_evidence(conn, file_id, principal.user_id)
        if row["status"] not in ("submitted", "in_review"):
            raise GateError(ErrorCode.INVALID_STATE, f"evidence_{row['status']}")
        conn.execute("""INSERT INTO evidence_reviews (file_id, result, reviewer_user_id, criteria_date)
                        VALUES (%s, %s, %s, %s)""", (file_id, body.result, principal.user_id, date.today()))
        conn.execute("UPDATE evidence_files SET status = 'reviewed', delete_after = %s WHERE file_id = %s",
                     (delete_after, file_id))
    audit.allow(request, target_type="evidence", target_id=str(file_id))
    return {"file_id": str(file_id), "status": "reviewed", "review_result": body.result,
            "delete_after": _iso(delete_after)}


@router.get("/internal/my-evidence-files")
def my_evidence_files(request: Request, member: Principal = Depends(member_via_transfer)):
    """내가 제출한 증빙의 상태만. 원본·심사자 정보는 주지 않는다. ※ 명세 외 추가"""
    owner = _member_of(member.user_id)
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT e.file_id, e.status, e.created_at, r.result
                 FROM evidence_files e LEFT JOIN evidence_reviews r ON r.file_id = e.file_id
                WHERE e.member_id = %s ORDER BY e.created_at DESC""",
            (owner["member_id"],)).fetchall()
    audit.allow(request, target_type="evidence_list")
    return {"items": [{"file_id": str(r["file_id"]), "status": r["status"],
                       "created_at": _iso(r["created_at"]), "review_result": r["result"]} for r in rows]}


# ======================================================================
# 관계·동의 (transfer-api 가 확인 / 회원 본인이 관리)
# ======================================================================
class DisclosureIn(BaseModel):
    member_id: uuid.UUID
    recipient_id: uuid.UUID
    consent_id: uuid.UUID
    purpose: str = Field(min_length=1, max_length=64)
    item: str = Field(default="profile", pattern="^(profile|photo|contact)$")


@router.post("/internal/disclosure-checks")
def disclosure_check(body: DisclosureIn, request: Request,
                     claims: dict = Depends(require_service("transfer-api"))):
    """정보 주체(member_id)가 수신자(recipient_id)에게 해당 항목·목적으로 유효한 동의를 했고,
    두 사람이 소개된 관계인지 확인한다. 결과만 답하고 근거는 감사 로그에 남긴다."""
    with db.connection() as conn:
        row = conn.execute(
            """SELECT c.expires_at, m.pseudo_id
                 FROM consents c
                 JOIN members m  ON m.member_id = c.member_id
                 JOIN members rm ON rm.member_id = c.counterpart_member_id
                 JOIN introductions i ON i.member_id = c.member_id AND i.counterpart_member_id = rm.member_id
                WHERE c.consent_id = %s AND c.member_id = %s AND rm.user_id = %s
                  AND c.item = %s AND c.purpose = %s
                  AND c.revoked_at IS NULL AND c.expires_at > now()""",
            (body.consent_id, body.member_id, body.recipient_id, body.item, body.purpose)).fetchone()
    if row is None:
        audit.deny(request, "consent_or_relation_invalid")
        return {"allowed": False}
    audit.allow(request, target_type="consent", target_id=str(body.consent_id))
    return {"allowed": True, "expires_at": _iso(row["expires_at"]), "member_pseudo_id": row["pseudo_id"]}


@router.get("/internal/my-consents")
def my_consents(request: Request, member: Principal = Depends(member_via_transfer)):
    """내 동의 목록 + 동의할 수 있는 소개 상대(counterparts). ※ 명세 외 추가"""
    owner = _member_of(member.user_id)
    with db.connection() as conn:
        items = conn.execute(
            """SELECT c.consent_id, cm.pseudo_id, c.item, c.purpose, c.expires_at, c.revoked_at
                 FROM consents c JOIN members cm ON cm.member_id = c.counterpart_member_id
                WHERE c.member_id = %s ORDER BY c.granted_at DESC""", (owner["member_id"],)).fetchall()
        counterparts = conn.execute(
            """SELECT cm.member_id, cm.pseudo_id FROM introductions i
                 JOIN members cm ON cm.member_id = i.counterpart_member_id
                WHERE i.member_id = %s ORDER BY cm.pseudo_id""", (owner["member_id"],)).fetchall()
    audit.allow(request, target_type="consent_list")
    return {"items": [{"consent_id": str(c["consent_id"]), "counterpart_pseudo_id": c["pseudo_id"],
                       "item": c["item"], "purpose": c["purpose"], "expires_at": _iso(c["expires_at"]),
                       "revoked_at": _iso(c["revoked_at"])} for c in items],
            "counterparts": [{"counterpart_member_id": str(c["member_id"]),
                              "counterpart_pseudo_id": c["pseudo_id"]} for c in counterparts]}


class ConsentIn(BaseModel):
    counterpart_member_id: uuid.UUID
    item: str = Field(pattern="^(profile|photo|contact)$")
    purpose: str = Field(min_length=1, max_length=64)
    expires_at: datetime


@router.post("/internal/my-consents", status_code=201)
def create_consent(body: ConsentIn, request: Request, member: Principal = Depends(member_via_transfer)):
    """동의 등록. 본인 명의로만, 소개된 상대에게만, 만료는 미래 1년 이내."""
    owner = _member_of(member.user_id)
    expires = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=timezone.utc)
    if not (_now() < expires <= _now() + timedelta(days=MAX_CONSENT_DAYS)):
        raise GateError(ErrorCode.INVALID_REQUEST, "consent_expiry_out_of_range")
    with db.connection() as conn:
        ok = conn.execute("SELECT 1 FROM introductions WHERE member_id = %s AND counterpart_member_id = %s",
                          (owner["member_id"], body.counterpart_member_id)).fetchone()
        if ok is None:
            raise GateError(ErrorCode.ACCESS_DENIED, "not_introduced")
        row = conn.execute(
            """INSERT INTO consents (member_id, counterpart_member_id, item, purpose, expires_at)
               VALUES (%s, %s, %s, %s, %s) RETURNING consent_id, granted_at""",
            (owner["member_id"], body.counterpart_member_id, body.item, body.purpose, expires)).fetchone()
    audit.allow(request, target_type="consent", target_id=str(row["consent_id"]))
    return {"consent_id": str(row["consent_id"]), "item": body.item, "purpose": body.purpose,
            "expires_at": _iso(expires), "granted_at": _iso(row["granted_at"])}


@router.post("/internal/my-consents/{consent_id}/revoke")
def revoke_consent(consent_id: uuid.UUID, request: Request, member: Principal = Depends(member_via_transfer)):
    """동의 철회 → 이후 이 동의에 기댄 신청·승인·다운로드는 disclosure-checks 에서 거부된다."""
    owner = _member_of(member.user_id)
    with db.connection() as conn:
        row = conn.execute("SELECT revoked_at FROM consents WHERE consent_id = %s AND member_id = %s",
                           (consent_id, owner["member_id"])).fetchone()
        if row is None:
            raise GateError(ErrorCode.NOT_FOUND, "consent_not_owned")
        if row["revoked_at"] is not None:
            raise GateError(ErrorCode.INVALID_STATE, "consent_already_revoked")
        done = conn.execute("UPDATE consents SET revoked_at = now() WHERE consent_id = %s RETURNING revoked_at",
                            (consent_id,)).fetchone()
    audit.allow(request, target_type="consent", target_id=str(consent_id))
    return {"consent_id": str(consent_id), "revoked_at": _iso(done["revoked_at"])}
