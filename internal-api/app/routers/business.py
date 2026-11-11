"""내부 업무 API (docs/api-spec.md 의 '내부').

원칙
- 권한 검사(역할·담당·배정·소유)는 자료를 읽거나 파일을 만들기 전에 끝낸다.
- 담당이 아닌 회원·배정되지 않은 증빙은 404 로 답해 존재 자체를 알리지 않는다.
- 응답 본문에는 판단 근거를 넣지 않고 감사 로그에만 남긴다.
- 회원 본인 기능은 transfer-api 서비스 토큰 + 회원 토큰을 검증하고, 회원은 토큰 sub 로만 정한다.
"""
import csv
import io
import json
import uuid
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
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
        row = conn.execute("SELECT member_id, pseudo_id FROM members WHERE user_id = %s AND status = 'active'",
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
# 회원 조회·관리 (counselor: 담당 회원만 / data_admin=총관리자: 전체)
# ======================================================================
MEMBER_ROLES = (Role.COUNSELOR, Role.DATA_ADMIN)
EDUCATION_LEVELS = ("고졸", "전문대졸", "4년제 대졸", "대학원졸")

# 담당 범위 조건: counselor 는 assignments 에 있는 회원만, data_admin 은 전체
SCOPE_SQL = """(%(role)s = 'data_admin' OR EXISTS (SELECT 1 FROM assignments a
                 WHERE a.member_id = m.member_id AND a.user_id = %(uid)s))"""

# 직원 화면에 보이는 프로필 항목 (실명·연락처는 넣지 않는다)
PROFILE_COLS = """m.member_id, m.pseudo_id, m.birth_date, m.height_cm, m.weight_kg,
                  m.education_level, m.school, m.major, m.job_group, m.company, m.introduction,
                  m.education_verified, m.employment_verified, m.status, m.withdrawn_at, m.created_at,
                  (m.user_id IS NOT NULL) AS has_account"""


def _scope(principal: Principal) -> dict:
    return {"role": principal.role, "uid": principal.user_id}


def _age(birth_date) -> int | None:
    """만 나이."""
    if not birth_date:
        return None
    today = _now().date()
    return today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))


def _profile(r) -> dict:
    return {"member_id": str(r["member_id"]), "pseudo_id": r["pseudo_id"],
            "birth_date": r["birth_date"].isoformat() if r["birth_date"] else None, "age": _age(r["birth_date"]),
            "height_cm": r["height_cm"], "weight_kg": r["weight_kg"],
            "education_level": r["education_level"], "school": r["school"], "major": r["major"],
            "job_group": r["job_group"], "company": r["company"], "introduction": r["introduction"],
            "education_verified": r["education_verified"], "employment_verified": r["employment_verified"],
            "status": r["status"], "has_account": r["has_account"], "created_at": _iso(r["created_at"])}


def _member_in_scope(conn, principal: Principal, member_id) -> dict:
    """범위 밖 회원은 404 (존재 여부를 알리지 않음)."""
    row = conn.execute(f"SELECT {PROFILE_COLS} FROM members m WHERE m.member_id = %(mid)s AND {SCOPE_SQL}",
                       {**_scope(principal), "mid": member_id}).fetchone()
    if row is None:
        raise GateError(ErrorCode.NOT_FOUND, "member_not_in_scope")
    return row


@router.get("/members")
def list_members(request: Request, principal: Principal = Depends(require(*MEMBER_ROLES))):
    """회원 목록: 프로필(회원 코드·만 나이·키·몸무게·학력·직군·직장·소개·증빙 상태)과 담당 직원·상태.
    실명·연락처는 주지 않는다."""
    with db.connection() as conn:
        rows = conn.execute(
            f"""SELECT {PROFILE_COLS},
                       (SELECT string_agg(u.pseudo_id || ' ' || u.display_name, ', ' ORDER BY u.pseudo_id)
                          FROM assignments a JOIN users u ON u.user_id = a.user_id
                         WHERE a.member_id = m.member_id) AS counselors,
                       (SELECT count(*) FROM consents c WHERE c.member_id = m.member_id
                           AND c.revoked_at IS NULL AND c.expires_at > now()) AS valid_consents,
                       (SELECT count(*) FROM evidence_files e WHERE e.member_id = m.member_id
                           AND e.status IN ('submitted', 'in_review')) AS open_evidence
                  FROM members m WHERE {SCOPE_SQL} ORDER BY m.status, m.pseudo_id""",
            _scope(principal)).fetchall()
    audit.allow(request, target_type="member_list_all" if principal.role == "data_admin" else "member_list")
    return {"items": [{**_profile(r), "counselors": r["counselors"], "valid_consents": r["valid_consents"],
                       "open_evidence": r["open_evidence"]} for r in rows]}


@router.get("/members/{member_id}")
def get_member(member_id: uuid.UUID, request: Request,
               principal: Principal = Depends(require(*MEMBER_ROLES))):
    """회원 상세: 프로필 + 이 회원이 정보 주체인 동의 + 매칭 상태. 범위 밖이면 404."""
    with db.connection() as conn:
        m = _member_in_scope(conn, principal, member_id)
        consents = conn.execute(
            """SELECT c.consent_id, c.consent_no, c.item, c.purpose, c.expires_at, c.revoked_at,
                      cm.pseudo_id AS counterpart_pseudo_id,
                      cm.user_id AS recipient_id
                 FROM consents c JOIN members cm ON cm.member_id = c.counterpart_member_id
                WHERE c.member_id = %s ORDER BY c.granted_at DESC""",
            (member_id,)).fetchall()
        matches = _match_rows(conn, member_id, staff=True)
    audit.allow(request, target_type="member", target_id=m["pseudo_id"])
    return {**_profile(m), "withdrawn_at": _iso(m["withdrawn_at"]),
            "consents": [{"consent_id": str(c["consent_id"]), "consent_label": f"C-{c['consent_no']}",
                          "item": c["item"], "purpose": c["purpose"],
                          "counterpart_pseudo_id": c["counterpart_pseudo_id"],
                          "recipient_id": str(c["recipient_id"]) if c["recipient_id"] else None,
                          "expires_at": _iso(c["expires_at"]), "revoked_at": _iso(c["revoked_at"]),
                          "valid": c["revoked_at"] is None and c["expires_at"] > _now()}
                         for c in consents],
            "matches": matches}


class MemberUpdateIn(BaseModel):
    birth_date: date | None = None
    height_cm: int | None = Field(default=None, ge=120, le=230)
    weight_kg: int | None = Field(default=None, ge=30, le=200)
    education_level: str | None = Field(default=None, pattern="^(고졸|전문대졸|4년제 대졸|대학원졸)$")
    school: str | None = Field(default=None, max_length=60)
    major: str | None = Field(default=None, max_length=60)
    job_group: str | None = Field(default=None, min_length=1, max_length=30)
    company: str | None = Field(default=None, max_length=60)
    introduction: str | None = Field(default=None, max_length=200)


# 이 항목이 바뀌면 해당 증빙을 다시 받아야 한다
EDU_FIELDS = {"education_level", "school", "major"}
JOB_FIELDS = {"company"}


@router.patch("/members/{member_id}")
def update_member(member_id: uuid.UUID, body: MemberUpdateIn, request: Request,
                  principal: Principal = Depends(require(*MEMBER_ROLES)),
                  _csrf: None = Depends(require_csrf)):
    """회원 정보 수정 (실명·연락처 제외). 담당 회원(총관리자는 전체), 탈퇴 회원은 불가.
    학력 항목이 바뀌면 학력 증빙, 직장이 바뀌면 재직 증빙 확인이 풀린다 (다시 심사). ※ 명세 외 추가"""
    fields = body.model_dump(exclude_unset=True)
    if not fields:
        raise GateError(ErrorCode.INVALID_REQUEST, "nothing_to_update")
    if fields.get("birth_date") and not (date(1900, 1, 1) <= fields["birth_date"] <= _now().date()):
        raise GateError(ErrorCode.INVALID_REQUEST, "birth_date_out_of_range")
    with db.connection() as conn:
        m = _member_in_scope(conn, principal, member_id)
        if m["status"] != "active":
            raise GateError(ErrorCode.INVALID_STATE, "member_withdrawn")
        changed = {k for k, v in fields.items() if v != m[k]}
        if EDU_FIELDS & changed:
            fields["education_verified"] = False
        if JOB_FIELDS & changed:
            fields["employment_verified"] = False
        sets = ", ".join(f"{k} = %({k})s" for k in fields)       # 키는 모델 필드 이름으로 고정
        conn.execute(f"UPDATE members SET {sets} WHERE member_id = %(mid)s", {**fields, "mid": member_id})
        row = conn.execute(f"SELECT {PROFILE_COLS} FROM members m WHERE m.member_id = %s", (member_id,)).fetchone()
    audit.allow(request, target_type="member", target_id=m["pseudo_id"])
    return _profile(row)


@router.post("/members/{member_id}/withdraw")
def withdraw_member(member_id: uuid.UUID, request: Request,
                    principal: Principal = Depends(require(*MEMBER_ROLES)),
                    _csrf: None = Depends(require_csrf)):
    """탈퇴 처리: 실명·연락처·학교·직장·소개 삭제, 상태 withdrawn, 주고받은 동의 철회, 매칭 취소.
    회원 행과 감사·반출 기록은 남긴다 (기록이 회원 ID 를 참조). ※ 명세 외 추가"""
    with db.connection() as conn:
        m = _member_in_scope(conn, principal, member_id)
        if m["status"] != "active":
            raise GateError(ErrorCode.INVALID_STATE, "member_withdrawn")
        conn.execute("""UPDATE members SET status = 'withdrawn', withdrawn_at = now(), name = '(탈퇴 회원)',
                               school = NULL, major = NULL, company = NULL,
                               introduction = NULL, contact_phone = NULL, contact_email = NULL
                         WHERE member_id = %s""", (member_id,))
        revoked = conn.execute("""UPDATE consents SET revoked_at = now()
                                   WHERE revoked_at IS NULL AND (member_id = %s OR counterpart_member_id = %s)""",
                               (member_id, member_id)).rowcount
        conn.execute("""UPDATE matches SET cancelled_at = now()
                         WHERE cancelled_at IS NULL AND (member_id = %s OR counterpart_member_id = %s)""",
                     (member_id, member_id))
    audit.allow(request, target_type="member", target_id=m["pseudo_id"])
    return {"member_id": str(member_id), "status": "withdrawn", "revoked_consents": revoked}


# ======================================================================
# 매칭 소개 자료 발송 요청 (counselor). 자료는 직원이 올리지 않고 서버가 회원 DB 로 만든다
# ======================================================================
def _detail_profile(m, name: str) -> dict:
    """매칭·동의 후 상대에게 주는 소개 자료.
    중계 검사 형식(4개 항목, 각 300자 이하)에 맞춘다: member_pseudo_id 자리에 실명(회원 코드는 관리자 전용이라 넣지 않음),
    age_band 자리에 만 나이.
    직장은 재직 증빙이 통과된 경우에만 넣는다. 연락처·증빙 원본은 넣지 않는다."""
    age = _age(m["birth_date"])
    edu = m["education_level"] or "비공개"
    if m["school"]:
        edu += f" ({m['school']}{' ' + m['major'] if m['major'] else ''})"
    edu += " · 학력 증빙 확인" if m["education_verified"] else ""
    job = m["job_group"] or "비공개"
    if m["employment_verified"] and m["company"]:
        job += f" · {m['company']} (재직 증빙 확인)"
    body = " / ".join(x for x in [
        f"키 {m['height_cm']}cm · 몸무게 {m['weight_kg']}kg (본인 신고)" if m["height_cm"] else None,
        f"학력 {edu}",
        f"소개 {m['introduction']}" if m["introduction"] else None] if x)
    return {"member_pseudo_id": name[:300], "age_band": f"만 {age}세" if age is not None else "비공개",
            "job_group": job[:300], "introduction": body[:300]}


class IntroductionIn(BaseModel):
    consent_id: uuid.UUID


@router.post("/members/{member_id}/introductions", status_code=201)
def request_introduction(member_id: uuid.UUID, body: IntroductionIn, request: Request,
                         principal: Principal = Depends(require(Role.COUNSELOR)),
                         _csrf: None = Depends(require_csrf)):
    """매칭으로 생긴 유효 동의(이 회원 → 상대)로 소개 자료 발송을 요청한다. ※ 명세 외 추가
    1) 담당 회원·유효 동의·상대 외부 계정 확인
    2) 소개 자료(실명·만 나이·키·몸무게·학력·직군·(재직 확인 시)직장·소개)를 회원 DB 에서 만든다
       — 연락처·증빙 원본은 넣지 않는다
    3) 중계에 파일 등록(형식 검사) → 발송 신청(승인 대기). 승인은 다른 승인자가 한다."""
    with db.connection() as conn:
        m = _member_in_scope(conn, principal, member_id)
        if m["status"] != "active":
            raise GateError(ErrorCode.INVALID_STATE, "member_withdrawn")
        c = conn.execute(
            """SELECT c.consent_id, c.purpose, c.expires_at, rm.user_id AS recipient_id
                 FROM consents c JOIN members rm ON rm.member_id = c.counterpart_member_id
                WHERE c.consent_id = %s AND c.member_id = %s AND c.item = 'profile'
                  AND c.revoked_at IS NULL AND c.expires_at > now() AND rm.status = 'active'""",
            (body.consent_id, member_id)).fetchone()
        if c is None:
            raise GateError(ErrorCode.INVALID_STATE, "consent_not_valid")
        if c["recipient_id"] is None:
            raise GateError(ErrorCode.INVALID_STATE, "recipient_has_no_account")
        name = conn.execute("SELECT name FROM members WHERE member_id = %s", (member_id,)).fetchone()["name"]
        seq = conn.execute("SELECT coalesce(max(seq), 0) + 1 AS n FROM intro_files WHERE member_id = %s",
                           (member_id,)).fetchone()["n"]
    profile = _detail_profile(m, name)
    data = json.dumps(profile, ensure_ascii=False).encode("utf-8")
    label = f"{m['pseudo_id']}_file{seq}"                      # 관리자 화면용 이름 (예: A-001_file1)
    up = transfer_client.call(request, "POST", "/api/transfer-files",
                              files={"file": (f"{label}.json", data, "application/json")})
    if up.status_code != 201:
        audit.deny(request, f"transfer_status_{up.status_code}")
        return transfer_client.relay(up)
    file_id = up.json()["file_id"]
    # 제공 기한: 최대 7일, 동의 만료를 넘지 않게 (경계보다 1분 앞)
    expires = min(_now() + timedelta(days=7), c["expires_at"]) - timedelta(minutes=1)
    req = transfer_client.call(request, "POST", "/api/export-requests", json={
        "file_id": file_id, "member_id": str(member_id), "recipient_id": str(c["recipient_id"]),
        "consent_id": str(c["consent_id"]), "purpose": c["purpose"], "expires_at": expires.isoformat()})
    if req.status_code != 201:
        audit.deny(request, f"transfer_status_{req.status_code}")
        return transfer_client.relay(req)
    request_id = req.json()["request_id"]
    with db.connection() as conn:
        conn.execute("""INSERT INTO intro_files (label, member_id, seq, consent_id, file_id, request_id, created_by)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                     (label, member_id, seq, c["consent_id"], file_id, request_id, principal.user_id))
    audit.allow(request, target_type="export_request", target_id=request_id)
    return {**req.json(), "label": label, "file_id": file_id, "profile": profile}


# ======================================================================
# 관리자 전체 회원 내보내기 (공격 ① 대상)
# ======================================================================
EXPORT_COLUMNS = ("pseudo_id", "name", "birth_date", "height_cm", "weight_kg", "education_level",
                  "school", "major", "job_group", "company", "contact_phone", "contact_email")


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
@router.post("/evidence-files", status_code=201)
async def submit_evidence(request: Request, file: UploadFile = File(...),
                          kind: str = Form("education", pattern="^(education|employment)$"),
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
        row = conn.execute(
            """INSERT INTO evidence_files (file_id, member_id, submitted_by, kind, storage_key,
                                           key_id, file_hash, status, delete_after)
               VALUES (%s, %s, %s, %s, %s, %s, %s, 'submitted', %s) RETURNING created_at""",
            (file_id, owner["member_id"], member.user_id, kind, key, storage.key_id(),
             storage.sha256_hex(data), _now() + timedelta(days=s.evidence_unreviewed_days))).fetchone()
    audit.allow(request, target_type="evidence", target_id=str(file_id))
    return {"file_id": str(file_id), "kind": kind, "status": "submitted", "created_at": _iso(row["created_at"])}


@router.get("/evidence-files")
def list_evidence(request: Request, principal: Principal = Depends(require(*MEMBER_ROLES))):
    """심사할 증빙 목록: counselor 는 담당 회원의 증빙만, 총관리자는 전체. 원본 내용은 넣지 않는다. ※ 명세 외 추가"""
    with db.connection() as conn:
        rows = conn.execute(
            f"""SELECT e.file_id, m.pseudo_id, m.member_id, e.kind, e.status, e.created_at,
                       e.delete_after, e.legal_hold,
                       r.result, u.pseudo_id AS reviewer
                  FROM evidence_files e JOIN members m ON m.member_id = e.member_id
                  LEFT JOIN evidence_reviews r ON r.file_id = e.file_id
                  LEFT JOIN users u ON u.user_id = e.reviewer_user_id
                 WHERE {SCOPE_SQL} ORDER BY e.created_at DESC""",
            _scope(principal)).fetchall()
    audit.allow(request, target_type="evidence_list")
    return {"items": [{"file_id": str(r["file_id"]), "member_id": str(r["member_id"]),
                       "member_pseudo_id": r["pseudo_id"], "kind": r["kind"],
                       "status": r["status"], "review_result": r["result"],
                       "reviewer": r["reviewer"], "created_at": _iso(r["created_at"]),
                       "delete_after": _iso(r["delete_after"]), "legal_hold": r["legal_hold"]} for r in rows]}


def _assigned_evidence(conn, file_id, principal: Principal) -> dict:
    """담당 회원의 증빙(총관리자는 전체)만. 범위 밖이면 404."""
    row = conn.execute(f"""SELECT e.file_id, e.member_id, e.kind, e.storage_key, e.status FROM evidence_files e
                             JOIN members m ON m.member_id = e.member_id
                            WHERE e.file_id = %(fid)s AND {SCOPE_SQL}""",
                       {**_scope(principal), "fid": file_id}).fetchone()
    if row is None:
        raise GateError(ErrorCode.NOT_FOUND, "evidence_not_in_scope")
    return row


@router.get("/evidence-files/{file_id}/content")
def read_evidence(file_id: uuid.UUID, request: Request,
                  principal: Principal = Depends(require(*MEMBER_ROLES))):
    """담당 직원(총관리자는 전체)만, 심사 중(submitted·in_review)에만 복호화해 보여 준다.
    처음 열면 상태가 in_review 로 바뀌고 연 직원이 심사자로 기록된다. 브라우저 저장·캐시를 막는 헤더를 붙인다."""
    with db.connection() as conn:
        row = _assigned_evidence(conn, file_id, principal)
        if row["status"] not in ("submitted", "in_review") or not row["storage_key"]:
            raise GateError(ErrorCode.INVALID_STATE, f"evidence_{row['status']}")
        if row["status"] == "submitted":
            conn.execute("UPDATE evidence_files SET status = 'in_review', reviewer_user_id = %s WHERE file_id = %s",
                         (principal.user_id, file_id))
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
                    principal: Principal = Depends(require(*MEMBER_ROLES)),
                    _csrf: None = Depends(require_csrf)):
    """심사 결과 저장(통과·반려) → 상태 reviewed, 원본 삭제 기한 = 지금 + 보관 기간."""
    s = get_settings()
    delete_after = _now() + timedelta(days=s.evidence_retention_days)
    with db.connection() as conn:
        row = _assigned_evidence(conn, file_id, principal)
        if row["status"] not in ("submitted", "in_review"):
            raise GateError(ErrorCode.INVALID_STATE, f"evidence_{row['status']}")
        conn.execute("""INSERT INTO evidence_reviews (file_id, result, reviewer_user_id, criteria_date)
                        VALUES (%s, %s, %s, %s)""", (file_id, body.result, principal.user_id, date.today()))
        conn.execute("""UPDATE evidence_files SET status = 'reviewed', delete_after = %s,
                               reviewer_user_id = %s WHERE file_id = %s""",
                     (delete_after, principal.user_id, file_id))
        if body.result == "passed":
            # 학력 증빙 통과 → 매칭 가능, 재직 증빙 통과 → 소개 자료에 직장 포함
            flag = "education_verified" if row["kind"] == "education" else "employment_verified"
            conn.execute(f"UPDATE members SET {flag} = true WHERE member_id = %s", (row["member_id"],))
    audit.allow(request, target_type="evidence", target_id=str(file_id))
    return {"file_id": str(file_id), "kind": row["kind"], "status": "reviewed", "review_result": body.result,
            "delete_after": _iso(delete_after)}


@router.get("/internal/my-evidence-files")
def my_evidence_files(request: Request, member: Principal = Depends(member_via_transfer)):
    """내가 제출한 증빙의 상태만. 원본·심사자 정보는 주지 않는다. ※ 명세 외 추가"""
    owner = _member_of(member.user_id)
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT e.file_id, e.kind, e.status, e.created_at, r.result
                 FROM evidence_files e LEFT JOIN evidence_reviews r ON r.file_id = e.file_id
                WHERE e.member_id = %s ORDER BY e.created_at DESC""",
            (owner["member_id"],)).fetchall()
    audit.allow(request, target_type="evidence_list")
    return {"items": [{"file_id": str(r["file_id"]), "kind": r["kind"], "status": r["status"],
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
                  AND m.status = 'active' AND rm.status = 'active'
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
            """SELECT c.consent_id, c.consent_no, cm.birth_date, cm.education_level,
                      c.item, c.purpose, c.expires_at, c.revoked_at
                 FROM consents c JOIN members cm ON cm.member_id = c.counterpart_member_id
                WHERE c.member_id = %s ORDER BY c.granted_at DESC""", (owner["member_id"],)).fetchall()
        counterparts = conn.execute(
            """SELECT cm.member_id, cm.birth_date, cm.education_level FROM introductions i
                 JOIN members cm ON cm.member_id = i.counterpart_member_id
                WHERE i.member_id = %s AND cm.status = 'active' ORDER BY cm.created_at""", (owner["member_id"],)).fetchall()
    audit.allow(request, target_type="consent_list")
    return {"items": [{"consent_id": str(c["consent_id"]), "consent_label": f"C-{c['consent_no']}",
                       "counterpart_label": _public_label(c["birth_date"], c["education_level"]),
                       "item": c["item"], "purpose": c["purpose"], "expires_at": _iso(c["expires_at"]),
                       "revoked_at": _iso(c["revoked_at"])} for c in items],
            "counterparts": [{"counterpart_member_id": str(c["member_id"]),
                              "counterpart_label": _public_label(c["birth_date"], c["education_level"])}
                             for c in counterparts]}


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


# ======================================================================
# 매칭 (회원 본인, transfer-api 경유). 서로 매칭을 누르면 양쪽 프로필 제공 동의를 만든다
# ======================================================================
MATCH_CONSENT_ITEM = "profile"
MATCH_CONSENT_PURPOSE = "introduction"
MATCH_CONSENT_DAYS = 30


def _public_label(birth_date, education_level) -> str:
    """회원 화면용 상대 표시 (회원 코드·실명 대신). 예: '소개 상대 · 만 32세 · 4년제 대졸'"""
    parts = ["소개 상대"]
    age = _age(birth_date)
    if age is not None:
        parts.append(f"만 {age}세")
    if education_level:
        parts.append(education_level)
    return " · ".join(parts)


def _match_rows(conn, member_id, staff: bool = False) -> list[dict]:
    """소개된 상대별 매칭 상태: 내가 눌렀는지, 상대가 눌렀는지, 성사 여부.
    회원용(staff=False)에는 회원 코드를 넣지 않는다 (코드는 관리자 전용)."""
    rows = conn.execute(
        """SELECT cm.member_id, cm.pseudo_id, cm.birth_date, cm.height_cm, cm.weight_kg,
                  cm.education_level, cm.education_verified, cm.job_group, cm.introduction,
                  mine.created_at AS i_at, theirs.created_at AS they_at
             FROM introductions i
             JOIN members cm ON cm.member_id = i.counterpart_member_id AND cm.status = 'active'
             LEFT JOIN matches mine   ON mine.member_id = i.member_id AND mine.counterpart_member_id = cm.member_id
                                     AND mine.cancelled_at IS NULL
             LEFT JOIN matches theirs ON theirs.member_id = cm.member_id AND theirs.counterpart_member_id = i.member_id
                                     AND theirs.cancelled_at IS NULL
            WHERE i.member_id = %s ORDER BY cm.pseudo_id""", (member_id,)).fetchall()
    return [{"counterpart_member_id": str(r["member_id"]),
             **({"counterpart_pseudo_id": r["pseudo_id"]} if staff else {}),
             "counterpart_label": _public_label(r["birth_date"], r["education_level"]),
             # 매칭 전 공개 카드: 만 나이·키·몸무게·학력 구분(학교 없음)·소개 (회원 코드·실명·학교·직장·연락처 없음)
             "card": {"age": _age(r["birth_date"]), "height_cm": r["height_cm"], "weight_kg": r["weight_kg"],
                      "education_level": r["education_level"], "introduction": r["introduction"]},
             "i_matched": r["i_at"] is not None, "they_matched": r["they_at"] is not None,
             "matched": r["i_at"] is not None and r["they_at"] is not None,
             "matched_at": _iso(max(r["i_at"], r["they_at"])) if r["i_at"] and r["they_at"] else None}
            for r in rows]


@router.get("/internal/my-matches")
def my_matches(request: Request, member: Principal = Depends(member_via_transfer)):
    """소개된 상대 목록과 매칭 상태. ※ 명세 외 추가"""
    owner = _member_of(member.user_id)
    with db.connection() as conn:
        items = _match_rows(conn, owner["member_id"])
        verified = conn.execute("SELECT education_verified FROM members WHERE member_id = %s",
                                (owner["member_id"],)).fetchone()["education_verified"]
    audit.allow(request, target_type="match_list")
    # can_match=false 이면 화면에서 "학력 증빙 승인 후 매칭할 수 있습니다" 안내
    return {"can_match": verified, "items": items}


class MatchIn(BaseModel):
    counterpart_member_id: uuid.UUID


def _grant_match_consent(conn, giver, receiver) -> None:
    """giver 가 receiver 에게 프로필 제공 동의 (이미 유효한 동의가 있으면 두지 않는다)."""
    exists = conn.execute(
        """SELECT 1 FROM consents WHERE member_id = %s AND counterpart_member_id = %s AND item = %s
              AND purpose = %s AND revoked_at IS NULL AND expires_at > now()""",
        (giver, receiver, MATCH_CONSENT_ITEM, MATCH_CONSENT_PURPOSE)).fetchone()
    if exists is None:
        conn.execute("""INSERT INTO consents (member_id, counterpart_member_id, item, purpose, expires_at)
                        VALUES (%s, %s, %s, %s, now() + make_interval(days => %s))""",
                     (giver, receiver, MATCH_CONSENT_ITEM, MATCH_CONSENT_PURPOSE, MATCH_CONSENT_DAYS))


@router.post("/internal/my-matches", status_code=201)
def create_match(body: MatchIn, request: Request, member: Principal = Depends(member_via_transfer)):
    """매칭 누르기. 소개된 상대에게만. 상대도 이미 눌렀으면 성사 → 서로 프로필 제공 동의(30일) 생성. ※ 명세 외 추가"""
    owner = _member_of(member.user_id)
    me_id, other = owner["member_id"], body.counterpart_member_id
    with db.connection() as conn:
        verified = conn.execute("SELECT education_verified FROM members WHERE member_id = %s",
                                (me_id,)).fetchone()["education_verified"]
        if not verified:
            raise GateError(ErrorCode.INVALID_STATE, "education_not_verified")   # 학력 증빙 통과 후 매칭 가능
        ok = conn.execute(
            """SELECT 1 FROM introductions i JOIN members cm ON cm.member_id = i.counterpart_member_id
                WHERE i.member_id = %s AND i.counterpart_member_id = %s AND cm.status = 'active'""",
            (me_id, other)).fetchone()
        if ok is None:
            raise GateError(ErrorCode.ACCESS_DENIED, "not_introduced")
        conn.execute("""INSERT INTO matches (member_id, counterpart_member_id) VALUES (%s, %s)
                        ON CONFLICT (member_id, counterpart_member_id)
                        DO UPDATE SET created_at = now(), cancelled_at = NULL
                        WHERE matches.cancelled_at IS NOT NULL""", (me_id, other))
        theirs = conn.execute("""SELECT 1 FROM matches WHERE member_id = %s AND counterpart_member_id = %s
                                    AND cancelled_at IS NULL""", (other, me_id)).fetchone()
        matched = theirs is not None
        if matched:
            _grant_match_consent(conn, me_id, other)
            _grant_match_consent(conn, other, me_id)
    audit.allow(request, target_type="match", target_id=str(other))
    return {"counterpart_member_id": str(other), "matched": matched}


@router.post("/internal/my-matches/{counterpart_member_id}/cancel")
def cancel_match(counterpart_member_id: uuid.UUID, request: Request,
                 member: Principal = Depends(member_via_transfer)):
    """매칭 취소. 성사된 매칭이었다면 매칭으로 만든 양쪽 프로필 동의를 함께 철회한다. ※ 명세 외 추가"""
    owner = _member_of(member.user_id)
    me_id, other = owner["member_id"], counterpart_member_id
    with db.connection() as conn:
        row = conn.execute("""UPDATE matches SET cancelled_at = now()
                               WHERE member_id = %s AND counterpart_member_id = %s AND cancelled_at IS NULL
                               RETURNING 1""", (me_id, other)).fetchone()
        if row is None:
            raise GateError(ErrorCode.NOT_FOUND, "match_not_found")
        revoked = conn.execute(
            """UPDATE consents SET revoked_at = now()
                WHERE revoked_at IS NULL AND item = %s AND purpose = %s
                  AND ((member_id = %s AND counterpart_member_id = %s)
                    OR (member_id = %s AND counterpart_member_id = %s))""",
            (MATCH_CONSENT_ITEM, MATCH_CONSENT_PURPOSE, me_id, other, other, me_id)).rowcount
    audit.allow(request, target_type="match", target_id=str(other))
    return {"counterpart_member_id": str(other), "cancelled": True, "revoked_consents": revoked}
