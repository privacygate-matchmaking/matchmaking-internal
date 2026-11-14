







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

from .. import audit, db, jobs, notify, storage, transfer_client
from ..auth.session import member_token_via_transfer, member_via_transfer, require, require_csrf, require_service
from ..config import get_settings

router = APIRouter(prefix="/api", tags=["business"])

CONSENT_ITEMS = ("profile", "photo", "contact")
MAX_CONSENT_DAYS = 365


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _member_of(user_id: str) -> dict:

    with db.connection() as conn:
        row = conn.execute("SELECT member_id, pseudo_id FROM members WHERE user_id = %s AND status = 'active'",
                           (user_id,)).fetchone()
    if row is None:
        raise GateError(ErrorCode.ACCESS_DENIED, "member_record_missing")
    return row


@router.get("/me")
def me(request: Request, principal: Principal = Depends(require(*STAFF_ROLES))):

    return {"user_id": principal.user_id, "pseudo_id": principal.pseudo_id, "role": principal.role,
            "csrf_token": request.state.csrf_token,
            "gate_mode": gate_mode.current(), "meeting_scheduling": True}


# ======================================================================

# ======================================================================
MEMBER_ROLES = (Role.COUNSELOR, Role.DATA_ADMIN)
WITHDRAW_GRACE_DAYS = 7
EDUCATION_LEVELS = ("고졸", "전문대졸", "4년제 대졸", "대학원졸")


SCOPE_SQL = """(%(role)s = 'data_admin' OR EXISTS (SELECT 1 FROM assignments a
                 WHERE a.member_id = m.member_id AND a.user_id = %(uid)s))"""


PROFILE_COLS = """m.member_id, m.pseudo_id, m.name, m.gender, m.birth_date, m.height_cm, m.weight_kg,
                  m.education_level, m.school, m.major, m.job_group, m.company, m.introduction,
                  m.education_verified, m.employment_verified, m.status, m.withdraw_requested_at, m.withdraw_at, m.withdraw_reason, m.created_at,
                  (SELECT u.role FROM users u WHERE u.user_id = m.withdraw_requested_by) AS withdraw_by_role,
                  (SELECT u.pseudo_id FROM users u WHERE u.user_id = m.withdraw_requested_by) AS withdraw_by,
                  (m.user_id IS NOT NULL) AS has_account"""


def _scope(principal: Principal) -> dict:
    return {"role": principal.role, "uid": principal.user_id}


def _age(birth_date) -> int | None:

    if not birth_date:
        return None
    today = _now().date()
    return today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))


def _profile(r) -> dict:
    return {"member_id": str(r["member_id"]), "pseudo_id": r["pseudo_id"], "name": r["name"], "gender": r["gender"],
            "birth_date": r["birth_date"].isoformat() if r["birth_date"] else None, "age": _age(r["birth_date"]),
            "height_cm": r["height_cm"], "weight_kg": r["weight_kg"],
            "education_level": r["education_level"], "school": r["school"], "major": r["major"],
            "job_group": r["job_group"], "company": r["company"], "introduction": r["introduction"],
            "education_verified": r["education_verified"], "employment_verified": r["employment_verified"],
            "status": r["status"], "withdraw_at": _iso(r["withdraw_at"]),
            "withdraw_requested_at": _iso(r["withdraw_requested_at"]), "withdraw_reason": r["withdraw_reason"],
            "withdraw_by": r["withdraw_by"], "withdraw_by_role": r["withdraw_by_role"],
            "has_account": r["has_account"], "created_at": _iso(r["created_at"])}


def _member_in_scope(conn, principal: Principal, member_id) -> dict:

    row = conn.execute(f"SELECT {PROFILE_COLS} FROM members m WHERE m.member_id = %(mid)s AND {SCOPE_SQL}",
                       {**_scope(principal), "mid": member_id}).fetchone()
    if row is None:
        raise GateError(ErrorCode.NOT_FOUND, "member_not_in_scope")
    return row


@router.get("/members")
def list_members(request: Request, principal: Principal = Depends(require(*MEMBER_ROLES))):


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

    with db.connection() as conn:
        m = _member_in_scope(conn, principal, member_id)
        consents = conn.execute(
            """SELECT c.consent_id, c.consent_no, c.item, c.purpose, c.expires_at, c.revoked_at,
                      cm.pseudo_id AS counterpart_pseudo_id, cm.name AS counterpart_name,
                      cm.user_id AS recipient_id
                 FROM consents c JOIN members cm ON cm.member_id = c.counterpart_member_id
                WHERE c.member_id = %s ORDER BY c.granted_at DESC""",
            (member_id,)).fetchall()
        matches = []
    audit.allow(request, target_type="member", target_id=m["pseudo_id"])
    return {**_profile(m),
            "consents": [{"consent_id": str(c["consent_id"]), "consent_label": f"C-{c['consent_no']}",
                          "item": c["item"], "purpose": c["purpose"],
                          "counterpart_pseudo_id": c["counterpart_pseudo_id"],
                          "counterpart_name": c["counterpart_name"],
                          "recipient_id": str(c["recipient_id"]) if c["recipient_id"] else None,
                          "expires_at": _iso(c["expires_at"]), "revoked_at": _iso(c["revoked_at"]),
                          "valid": c["revoked_at"] is None and c["expires_at"] > _now()}
                         for c in consents],
            "matches": matches}


class MemberUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=40)
    gender: str | None = Field(default=None, pattern="^(남|여)$")
    birth_date: date | None = None
    height_cm: int | None = Field(default=None, ge=120, le=230)
    weight_kg: int | None = Field(default=None, ge=30, le=200)
    education_level: str | None = Field(default=None, pattern="^(고졸|전문대졸|4년제 대졸|대학원졸)$")
    school: str | None = Field(default=None, max_length=60)
    major: str | None = Field(default=None, max_length=60)
    job_group: str | None = Field(default=None, min_length=1, max_length=30)
    company: str | None = Field(default=None, max_length=60)
    introduction: str | None = Field(default=None, max_length=200)



EDU_FIELDS = {"education_level", "school", "major"}
JOB_FIELDS = {"company"}


@router.patch("/members/{member_id}")
def update_member(member_id: uuid.UUID, body: MemberUpdateIn, request: Request,
                  principal: Principal = Depends(require(*MEMBER_ROLES)),
                  _csrf: None = Depends(require_csrf)):


    fields = body.model_dump(exclude_unset=True)
    if "name" in fields and not fields["name"]:
        fields.pop("name")
    if not fields:
        raise GateError(ErrorCode.INVALID_REQUEST, "nothing_to_update")
    if fields.get("birth_date") and not (date(1900, 1, 1) <= fields["birth_date"] <= _now().date()):
        raise GateError(ErrorCode.INVALID_REQUEST, "birth_date_out_of_range")
    with db.connection() as conn:
        m = _member_in_scope(conn, principal, member_id)
        if m["status"] != "active":
            raise GateError(ErrorCode.INVALID_STATE, "member_not_active")
        changed = {k for k, v in fields.items() if v != m[k]}
        if EDU_FIELDS & changed:
            fields["education_verified"] = False
        if JOB_FIELDS & changed:
            fields["employment_verified"] = False
        sets = ", ".join(f"{k} = %({k})s" for k in fields)
        conn.execute(f"UPDATE members SET {sets} WHERE member_id = %(mid)s", {**fields, "mid": member_id})
        row = conn.execute(f"SELECT {PROFILE_COLS} FROM members m WHERE m.member_id = %s", (member_id,)).fetchone()
    audit.allow(request, target_type="member", target_id=m["pseudo_id"])
    return _profile(row)


class WithdrawIn(BaseModel):
    mode: str = Field(default="scheduled", pattern="^(scheduled|immediate)$")
    reason: str | None = Field(default=None, max_length=200)


@router.post("/members/{member_id}/withdraw")
def withdraw_member(member_id: uuid.UUID, body: WithdrawIn, request: Request,
                    principal: Principal = Depends(require(*MEMBER_ROLES)),
                    _csrf: None = Depends(require_csrf)):






    if body.mode == "immediate" and principal.role != Role.DATA_ADMIN.value:
        raise GateError(ErrorCode.ACCESS_DENIED, "immediate_withdraw_admin_only")
    reason = (body.reason or "").strip() or None
    with db.connection() as conn:
        m = _member_in_scope(conn, principal, member_id)
        if body.mode == "scheduled":
            if m["status"] != "active":
                raise GateError(ErrorCode.INVALID_STATE, "already_withdraw_pending")
            row = conn.execute(
                """UPDATE members SET status = 'withdraw_pending', withdraw_requested_at = now(),
                          withdraw_at = now() + make_interval(days => %s),
                          withdraw_requested_by = %s, withdraw_reason = %s
                    WHERE member_id = %s RETURNING withdraw_at""",
                (WITHDRAW_GRACE_DAYS, principal.user_id, reason, member_id)).fetchone()
            who = f"{m['pseudo_id']} {m['name']}"
            text = f"{who} 회원이 탈퇴 예정이 되었습니다 (7일 후 삭제){' · 사유: ' + reason if reason else ''}"
            if principal.role == Role.DATA_ADMIN.value:
                notify.to_counselors_of(conn, member_id, "withdraw_requested", "총관리자가 탈퇴 요청함", text, "manage")
            else:
                notify.to_role(conn, "data_admin", "withdraw_requested", f"탈퇴 요청 ({principal.pseudo_id})", text, "manage")
        else:


            conn.execute(
                """UPDATE members SET
                          withdraw_requested_by = CASE WHEN status = 'active' THEN %(by)s ELSE withdraw_requested_by END,
                          withdraw_reason = CASE
                              WHEN status = 'active' THEN %(reason)s
                              WHEN %(reason)s::text IS NOT NULL AND withdraw_requested_by IS DISTINCT FROM user_id THEN %(reason)s
                              ELSE withdraw_reason END
                    WHERE member_id = %(mid)s""",
                {"by": principal.user_id, "reason": reason, "mid": member_id})

            notify.to_counselors_of(conn, member_id, "member_deleted", "회원 즉시 탈퇴",
                                    f"{m['pseudo_id']} {m['name']} 회원 정보가 총관리자에 의해 삭제되었습니다.",
                                    "manage", exclude=principal.user_id)
    if body.mode == "scheduled":
        audit.allow(request, target_type="member_withdraw_scheduled", target_id=m["pseudo_id"])
        return {"member_id": str(member_id), "status": "withdraw_pending", "withdraw_at": _iso(row["withdraw_at"])}
    files = jobs.purge_member(member_id)
    audit.allow(request, target_type="member_purged", target_id=m["pseudo_id"])
    return {"member_id": str(member_id), "status": "deleted", "deleted_evidence_files": files}


@router.post("/members/{member_id}/withdraw/cancel")
def cancel_withdraw(member_id: uuid.UUID, request: Request,
                    principal: Principal = Depends(require(*MEMBER_ROLES)),
                    _csrf: None = Depends(require_csrf)):

    with db.connection() as conn:
        m = _member_in_scope(conn, principal, member_id)
        if m["status"] != "withdraw_pending":
            raise GateError(ErrorCode.INVALID_STATE, "not_withdraw_pending")
        if m["withdraw_by_role"] == Role.DATA_ADMIN.value and principal.role != Role.DATA_ADMIN.value:
            raise GateError(ErrorCode.ACCESS_DENIED, "withdraw_requested_by_admin")
        conn.execute("""UPDATE members SET status = 'active', withdraw_requested_at = NULL, withdraw_at = NULL,
                               withdraw_requested_by = NULL, withdraw_reason = NULL
                         WHERE member_id = %s""", (member_id,))
        text = f"{m['pseudo_id']} {m['name']} 회원의 탈퇴가 철회되었습니다 ({principal.pseudo_id})."
        notify.to_counselors_of(conn, member_id, "withdraw_cancelled", "탈퇴 철회", text, "manage", exclude=principal.user_id)
        notify.to_role(conn, "data_admin", "withdraw_cancelled", "탈퇴 철회", text, "manage", exclude=principal.user_id)
    audit.allow(request, target_type="member_withdraw_cancelled", target_id=m["pseudo_id"])
    return {"member_id": str(member_id), "status": "active"}


# ======================================================================

# ======================================================================
def _detail_profile(m, name: str) -> dict:




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
    return {"schema_version": 2, "member_id": str(m["member_id"]), "display_name": name[:300], "age_band": f"만 {age}세" if age is not None else "비공개",
            "job_group": job[:300], "introduction": body[:300]}


class IntroductionIn(BaseModel):
    consent_id: uuid.UUID


@router.post("/members/{member_id}/introductions", status_code=201)
def request_introduction(member_id: uuid.UUID, body: IntroductionIn, request: Request,
                         principal: Principal = Depends(require(Role.COUNSELOR)),
                         _csrf: None = Depends(require_csrf)):





    with db.connection() as conn:
        m = _member_in_scope(conn, principal, member_id)
        if m["status"] != "active":
            raise GateError(ErrorCode.INVALID_STATE, "member_not_active")
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
    label = f"{m['pseudo_id']}_file{seq}"
    up = transfer_client.call(request, "POST", "/api/transfer-files",
                              files={"file": (f"{label}.json", data, "application/json")})
    if up.status_code != 201:
        audit.deny(request, f"transfer_status_{up.status_code}")
        return transfer_client.relay(up)
    file_id = up.json()["file_id"]

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
        notify.to_role(conn, "approver", "intro_requested", "새 소개 자료 발송 신청",
                       f"{label} ({m['pseudo_id']} {m['name']}) · 신청 {principal.pseudo_id}", "approvals")
    audit.allow(request, target_type="export_request", target_id=request_id)
    return {**req.json(), "label": label, "file_id": file_id, "profile": profile}


# ======================================================================

# ======================================================================
EXPORT_COLUMNS = ("pseudo_id", "name", "gender", "birth_date", "height_cm", "weight_kg", "education_level",
                  "school", "major", "job_group", "company", "contact_phone", "contact_email")


@router.post("/admin/member-exports", status_code=201)
def create_member_export(request: Request,
                         principal: Principal = Depends(require(Role.DATA_ADMIN, baseline_open=True)),
                         _csrf: None = Depends(require_csrf)):


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

        odd = principal.role != Role.DATA_ADMIN.value
        notify.to_role(conn, "data_admin", "member_export",
                       "⚠ 비정상 전체 회원 내보내기" if odd else "전체 회원 내보내기 실행",
                       f"{principal.pseudo_id}({principal.role}) · {len(rows)}건", "manage",
                       exclude=None if odd else principal.user_id)
    audit.allow(request, target_type="member_export", target_id=str(export_id))
    return {"export_id": str(export_id), "row_count": len(rows), "created_at": _iso(row["created_at"])}


@router.get("/admin/member-exports")
def admin_list_exports(request: Request, principal: Principal = Depends(require(Role.DATA_ADMIN))):

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

# ======================================================================
@router.post("/evidence-files", status_code=201)
async def submit_evidence(request: Request, file: UploadFile = File(...),
                          kind: str = Form("education", pattern="^(education|employment)$"),
                          member: Principal = Depends(member_via_transfer)):


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
        kind_ko = "재직" if kind == "employment" else "학력"
        text = f"{notify.member_label(conn, owner['member_id'])} 회원이 {kind_ko} 증빙을 제출했습니다."
        notify.to_counselors_of(conn, owner["member_id"], "evidence_submitted", "새 증빙 서류", text, "evidence")
        notify.to_role(conn, "data_admin", "evidence_submitted", "새 증빙 서류", text, "evidence")
    audit.allow(request, target_type="evidence", target_id=str(file_id))
    return {"file_id": str(file_id), "kind": kind, "status": "submitted", "created_at": _iso(row["created_at"])}


@router.get("/evidence-files")
def list_evidence(request: Request, principal: Principal = Depends(require(*MEMBER_ROLES))):

    with db.connection() as conn:
        rows = conn.execute(
            f"""SELECT e.file_id, m.pseudo_id, m.name, m.member_id, e.kind, e.status, e.created_at,
                       e.delete_after, e.legal_hold,
                       r.result, u.pseudo_id AS reviewer
                  FROM evidence_files e JOIN members m ON m.member_id = e.member_id
                  LEFT JOIN evidence_reviews r ON r.file_id = e.file_id
                  LEFT JOIN users u ON u.user_id = e.reviewer_user_id
                 WHERE {SCOPE_SQL} ORDER BY e.created_at DESC""",
            _scope(principal)).fetchall()
    audit.allow(request, target_type="evidence_list")
    return {"items": [{"file_id": str(r["file_id"]), "member_id": str(r["member_id"]),
                       "member_pseudo_id": r["pseudo_id"], "member_name": r["name"], "kind": r["kind"],
                       "status": r["status"], "review_result": r["result"],
                       "reviewer": r["reviewer"], "created_at": _iso(r["created_at"]),
                       "delete_after": _iso(r["delete_after"]), "legal_hold": r["legal_hold"]} for r in rows]}


def _assigned_evidence(conn, file_id, principal: Principal) -> dict:

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

            flag = "education_verified" if row["kind"] == "education" else "employment_verified"
            conn.execute(f"UPDATE members SET {flag} = true WHERE member_id = %s", (row["member_id"],))
    audit.allow(request, target_type="evidence", target_id=str(file_id))
    return {"file_id": str(file_id), "kind": row["kind"], "status": "reviewed", "review_result": body.result,
            "delete_after": _iso(delete_after)}


@router.get("/internal/my-evidence-files")
def my_evidence_files(request: Request, member: Principal = Depends(member_via_transfer)):

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


    with db.connection() as conn:
        row = conn.execute(
            """SELECT c.expires_at, m.member_id
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
    return {"allowed": True, "expires_at": _iso(row["expires_at"]), "member_id": str(row["member_id"])}


@router.get("/internal/my-consents")
def my_consents(request: Request, member: Principal = Depends(member_via_transfer)):

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

# ======================================================================


def _public_label(birth_date, education_level) -> str:

    parts = ["소개 상대"]
    age = _age(birth_date)
    if age is not None:
        parts.append(f"만 {age}세")
    if education_level:
        parts.append(education_level)
    return " · ".join(parts)


@router.get("/internal/my-matches")
def my_matches(request: Request, member: Principal = Depends(member_via_transfer)):

    raise GateError(ErrorCode.INVALID_STATE, "use_paid_matching_api")


class MatchIn(BaseModel):
    counterpart_member_id: uuid.UUID


@router.post("/internal/my-matches", status_code=201)
def create_match(body: MatchIn, request: Request, member: Principal = Depends(member_via_transfer)):

    raise GateError(ErrorCode.INVALID_STATE, "use_paid_matching_api")


@router.post("/internal/my-matches/{counterpart_member_id}/cancel")
def cancel_match(counterpart_member_id: uuid.UUID, request: Request,
                 member: Principal = Depends(member_via_transfer)):

    raise GateError(ErrorCode.INVALID_STATE, "use_paid_matching_api")


# ======================================================================

# ======================================================================
def _status_message(status: str, by_staff: bool, reason: str | None, when) -> str:
    day = when.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d") if when else ""
    why = f" 사유: {reason}" if reason else " 사유: (입력 없음)"
    if status == "withdrawn":
        return f"관리자에 의해 탈퇴 처리된 계정입니다.{why}" if by_staff else "탈퇴된 계정입니다."
    if by_staff:
        return f"관리자에 의해 탈퇴 처리 중인 계정입니다 ({day} 삭제 예정).{why} 문의는 담당 상담 직원에게 해 주세요."
    return f"탈퇴 신청한 계정입니다 ({day} 삭제 예정). 그 전까지 탈퇴를 철회할 수 있습니다."


@router.get("/internal/my-status")
def my_status(request: Request, sub: str = Depends(member_token_via_transfer)):






    with db.connection() as conn:
        m = conn.execute(
            """SELECT m.status, m.withdraw_at, m.withdraw_reason,
                      (m.withdraw_requested_by IS DISTINCT FROM m.user_id) AS by_staff
                 FROM members m JOIN users u ON u.user_id = m.user_id
                WHERE m.user_id = %s AND u.active AND u.role = 'member'""", (sub,)).fetchone()
        notice = None if m else conn.execute(
            "SELECT by_staff, reason, withdrawn_at FROM withdrawal_notices WHERE user_id = %s", (sub,)).fetchone()
    audit.allow(request, target_type="member_status")
    if m and m["status"] == "active":
        return {"status": "active", "message": None}
    if m:
        by_staff, reason = m["by_staff"], (m["withdraw_reason"] if m["by_staff"] else None)
        return {"status": "withdraw_pending", "by": "staff" if by_staff else "self", "reason": reason,
                "withdraw_at": _iso(m["withdraw_at"]), "can_cancel": not by_staff,
                "message": _status_message("withdraw_pending", by_staff, reason, m["withdraw_at"])}
    if notice:
        reason = notice["reason"] if notice["by_staff"] else None
        return {"status": "withdrawn", "by": "staff" if notice["by_staff"] else "self", "reason": reason,
                "withdrawn_at": _iso(notice["withdrawn_at"]),
                "message": _status_message("withdrawn", notice["by_staff"], reason, None)}
    return {"status": "not_registered", "message": "회원 정보가 없습니다. 고객센터로 문의해 주세요."}


class MyWithdrawIn(BaseModel):
    reason: str | None = Field(default=None, max_length=200)


@router.post("/internal/my-withdrawal")
def my_withdraw(body: MyWithdrawIn, request: Request, member: Principal = Depends(member_via_transfer)):

    owner = _member_of(member.user_id)
    reason = (body.reason or "").strip() or None
    with db.connection() as conn:
        row = conn.execute(
            """UPDATE members SET status = 'withdraw_pending', withdraw_requested_at = now(),
                      withdraw_at = now() + make_interval(days => %s),
                      withdraw_requested_by = user_id, withdraw_reason = %s
                WHERE member_id = %s AND status = 'active' RETURNING withdraw_at""",
            (WITHDRAW_GRACE_DAYS, reason, owner["member_id"])).fetchone()
        if row is None:
            raise GateError(ErrorCode.INVALID_STATE, "already_withdraw_pending")
        text = f"{notify.member_label(conn, owner['member_id'])} 회원이 직접 탈퇴를 신청했습니다 (7일 후 삭제)."
        notify.to_counselors_of(conn, owner["member_id"], "withdraw_requested", "회원 탈퇴 신청", text, "manage")
        notify.to_role(conn, "data_admin", "withdraw_requested", "회원 탈퇴 신청", text, "manage")
    audit.allow(request, target_type="member_withdraw_self", target_id=owner["pseudo_id"])
    return {"status": "withdraw_pending", "withdraw_at": _iso(row["withdraw_at"])}


@router.post("/internal/my-withdrawal/cancel")
def my_withdraw_cancel(request: Request, member: Principal = Depends(member_via_transfer)):

    with db.connection() as conn:
        m = conn.execute(
            """SELECT member_id, pseudo_id, (withdraw_requested_by = user_id) AS by_self FROM members
                WHERE user_id = %s AND status = 'withdraw_pending'""", (member.user_id,)).fetchone()
        if m is None:
            raise GateError(ErrorCode.INVALID_STATE, "not_withdraw_pending")
        if not m["by_self"]:
            raise GateError(ErrorCode.ACCESS_DENIED, "withdraw_requested_by_staff")
        conn.execute("""UPDATE members SET status = 'active', withdraw_requested_at = NULL, withdraw_at = NULL,
                               withdraw_requested_by = NULL, withdraw_reason = NULL
                         WHERE member_id = %s""", (m["member_id"],))
        text = f"{notify.member_label(conn, m['member_id'])} 회원이 탈퇴 신청을 철회했습니다."
        notify.to_counselors_of(conn, m["member_id"], "withdraw_cancelled", "탈퇴 철회", text, "manage")
        notify.to_role(conn, "data_admin", "withdraw_cancelled", "탈퇴 철회", text, "manage")
    audit.allow(request, target_type="member_withdraw_self_cancelled", target_id=m["pseudo_id"])
    return {"status": "active"}


# ======================================================================

# ======================================================================
@router.get("/notifications")
def list_notifications(request: Request, principal: Principal = Depends(require(*STAFF_ROLES))):

    with db.connection() as conn:
        rows = conn.execute("""SELECT notification_id, kind, title, body, link_view, created_at, read_at
                                 FROM notifications WHERE user_id = %s ORDER BY created_at DESC LIMIT 100""",
                            (principal.user_id,)).fetchall()
        unread = conn.execute("SELECT count(*) AS n FROM notifications WHERE user_id = %s AND read_at IS NULL",
                              (principal.user_id,)).fetchone()["n"]
    return {"unread": unread,
            "items": [{"notification_id": str(r["notification_id"]), "kind": r["kind"], "title": r["title"],
                       "body": r["body"], "link_view": r["link_view"], "created_at": _iso(r["created_at"]),
                       "read": r["read_at"] is not None} for r in rows]}


class NotificationSelect(BaseModel):
    ids: list[uuid.UUID] = Field(default_factory=list, max_length=200)
    all: bool = False


def _unread(conn, user_id) -> int:
    return conn.execute("SELECT count(*) AS n FROM notifications WHERE user_id = %s AND read_at IS NULL",
                        (user_id,)).fetchone()["n"]


@router.post("/notifications/read")
def read_notifications(body: NotificationSelect, request: Request,
                       principal: Principal = Depends(require(*STAFF_ROLES)),
                       _csrf: None = Depends(require_csrf)):

    with db.connection() as conn:
        if body.all:
            n = conn.execute("UPDATE notifications SET read_at = now() WHERE user_id = %s AND read_at IS NULL",
                             (principal.user_id,)).rowcount
        else:
            n = conn.execute("""UPDATE notifications SET read_at = now()
                                 WHERE user_id = %s AND read_at IS NULL AND notification_id = ANY(%s)""",
                             (principal.user_id, [str(i) for i in body.ids])).rowcount
        unread = _unread(conn, principal.user_id)
    return {"updated": n, "unread": unread}


@router.post("/notifications/delete")
def delete_notifications(body: NotificationSelect, request: Request,
                         principal: Principal = Depends(require(*STAFF_ROLES)),
                         _csrf: None = Depends(require_csrf)):

    with db.connection() as conn:
        if body.all:
            n = conn.execute("DELETE FROM notifications WHERE user_id = %s", (principal.user_id,)).rowcount
        else:
            n = conn.execute("DELETE FROM notifications WHERE user_id = %s AND notification_id = ANY(%s)",
                             (principal.user_id, [str(i) for i in body.ids])).rowcount
        unread = _unread(conn, principal.user_id)
    return {"deleted": n, "unread": unread}
