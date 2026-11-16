"""직원 가입 신청과 총관리자 승인. ※ 명세 외 추가

- POST /api/staff-signups: 로그인 전 내부 화면 가입 폼. Origin 일치 + 요청 횟수 제한.
  Keycloak 계정은 비활성·업무 역할 없음으로 만들고(로그인 불가), 신청 기록(staff_signups)을 남겨 총관리자에게 알린다.
- GET /api/staff-signups, POST …/{signup_id}/approve|reject: 총관리자(data_admin)만, CSRF 확인.
  승인 = Keycloak 활성화 + 역할 그룹(counselors·approvers) + approve_staff_signup()으로 users 등록(직원 코드 발급).
  거절 = Keycloak 계정·신청 기록 삭제.
- 신청 가능한 역할은 상담(counselor)·승인(approver). 총관리자 가입은 받지 않는다.
  승인 담당자 계정이 새로 승인되면 기존 승인 담당자에게도 알린다 (총관리자 혼자 반출 승인 권한을 만드는 일을 드러내기 위함).
- 비밀번호는 Keycloak 에만 저장한다. 업무 DB·감사 로그·알림·응답에 남기지 않는다.
"""
import re
import threading
import time
import uuid
from collections import deque
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, Request
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import Principal
from pydantic import BaseModel, ConfigDict, Field

from .. import audit, db, keycloak_admin, notify
from ..auth.session import require, require_csrf
from ..config import get_settings

router = APIRouter(prefix="/api")

USERNAME = re.compile(r"^[a-z][a-z0-9_]{3,19}$")
EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,24}$")
ROLE_KO = {"counselor": "상담 직원", "approver": "승인 담당자"}
FAILED = "가입 신청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요."


class Limiter:
    """메모리 기반 요청 횟수 제한 (internal-api 프로세스 기준)."""
    def __init__(self, per_client=5, overall=30, window=600, clock=time.monotonic):
        self.per_client, self.overall, self.window, self.clock = per_client, overall, window, clock
        self.hits, self.all, self.lock = {}, deque(), threading.Lock()

    def allow(self, key) -> bool:
        now = self.clock()
        with self.lock:
            while self.all and self.all[0] <= now - self.window:
                self.all.popleft()
            mine = self.hits.get(key, deque())
            while mine and mine[0] <= now - self.window:
                mine.popleft()
            if len(self.all) >= self.overall or len(mine) >= self.per_client:
                return False
            self.all.append(now)
            mine.append(now)
            self.hits[key] = mine
            return True


limiter = Limiter()


def public_staff_signup(request: Request) -> bool:
    # 세션이 없으므로 CSRF 토큰 대신 Origin 을 확인 (내부 화면의 가입 폼에서 온 요청만)
    if request.headers.get("Origin") != get_settings().app_base_url:
        raise GateError(ErrorCode.ACCESS_DENIED, "origin_mismatch")
    # nginx 가 X-Forwarded-For 를 접속 주소로 덮어쓴다
    client = request.headers.get("X-Forwarded-For") or (request.client.host if request.client else "-")
    if not limiter.allow(client):
        raise GateError(ErrorCode.INVALID_STATE, "signup_rate_limited", message="가입 신청이 많습니다. 잠시 후 다시 시도해 주세요.")
    return True


setattr(public_staff_signup, "__privacygate_policy__", "public:staff-signup")


class StaffSignupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=4, max_length=20)
    password: str = Field(min_length=12, max_length=64)
    name: str = Field(min_length=1, max_length=30)
    email: str = Field(max_length=200)
    requested_role: Literal["counselor", "approver"]


def _bad(reason: str, message: str):
    raise GateError(ErrorCode.INVALID_REQUEST, reason, message=message)


def clean(body: StaffSignupIn) -> dict:
    if not USERNAME.match(body.username):
        _bad("username_invalid", "아이디는 영문 소문자로 시작하는 4~20자(영문 소문자·숫자·_)로 입력하세요.")
    if body.username in body.password.lower():
        _bad("password_contains_username", "비밀번호에 아이디를 넣을 수 없습니다.")
    if body.password != body.password.strip():
        _bad("password_invalid", "비밀번호 앞뒤에 공백을 넣을 수 없습니다.")
    name = body.name.strip()
    if not name or any(ch in name for ch in "<>\r\n\t"):
        _bad("name_invalid", "이름을 확인하세요.")
    email = body.email.strip()
    if not EMAIL.match(email):
        _bad("email_invalid", "이메일 형식을 확인하세요.")
    return {"username": body.username, "name": name, "email": email, "requested_role": body.requested_role}


KC_MESSAGES = {
    "account_exists": (ErrorCode.INVALID_STATE, "이미 사용 중인 아이디 또는 이메일입니다."),
    "password_policy": (ErrorCode.INVALID_REQUEST, "비밀번호는 12자 이상이며 아이디를 포함할 수 없습니다."),
    "account_invalid": (ErrorCode.INVALID_REQUEST, "입력한 계정 정보를 확인하세요."),
}


def save_signup(conn, user_id: str, v: dict) -> str:
    row = conn.execute(
        """INSERT INTO staff_signups (user_id, username, name, email, requested_role)
           VALUES (%s::uuid, %s, %s, %s, %s) RETURNING signup_id""",
        (user_id, v["username"], v["name"], v["email"], v["requested_role"])).fetchone()
    notify.to_role(conn, "data_admin", "staff_signup_requested", "직원 가입 신청",
                   f"{v['name']}({v['username']}) 님이 {ROLE_KO[v['requested_role']]} 가입을 신청했습니다.", "staff_signups")
    return str(row["signup_id"])


@router.post("/staff-signups", status_code=201)
def staff_signup(body: StaffSignupIn, request: Request, _ok: bool = Depends(public_staff_signup)):
    values = clean(body)
    if not keycloak_admin.enabled():
        raise GateError(ErrorCode.INVALID_STATE, "signup_not_enabled", message="가입 신청을 사용할 수 없습니다. 총관리자에게 문의하세요.")
    try:
        user_id = keycloak_admin.create_staff_pending(body.username, body.password, values["email"], values["name"])
    except keycloak_admin.KeycloakAdminError as exc:
        reason = str(exc)
        audit.deny(request, f"staff_signup:{reason}", action="staff_signup.request")
        code, message = KC_MESSAGES.get(reason, (ErrorCode.INTERNAL_ERROR, FAILED))
        raise GateError(code, reason, message=message)
    except httpx.HTTPError:
        audit.deny(request, "staff_signup:identity_unavailable", action="staff_signup.request")
        raise GateError(ErrorCode.INTERNAL_ERROR, "identity_unavailable", message=FAILED)
    try:
        with db.connection() as conn:
            signup_id = save_signup(conn, user_id, values)
    except Exception:
        try:
            keycloak_admin.delete_pending_staff(user_id)
        except (keycloak_admin.KeycloakAdminError, httpx.HTTPError):
            pass
        audit.deny(request, "staff_signup:db_failed", action="staff_signup.request")
        raise GateError(ErrorCode.INTERNAL_ERROR, "staff_signup_db_failed", message=FAILED)
    audit.allow(request, action="staff_signup.request", target_type="staff_signup", target_id=signup_id,
                reason=values["requested_role"])
    return {"status": "pending"}


def _iso(value):
    return value.isoformat() if value is not None else None


@router.get("/staff-signups")
def list_staff_signups(request: Request, principal: Principal = Depends(require("data_admin"))):
    with db.connection() as conn:
        rows = conn.execute("""SELECT signup_id, username, name, email, requested_role, created_at
                                 FROM staff_signups ORDER BY created_at""").fetchall()
    audit.allow(request, target_type="staff_signups")
    return {"items": [{"signup_id": str(r["signup_id"]), "username": r["username"], "name": r["name"],
                       "email": r["email"], "requested_role": r["requested_role"],
                       "created_at": _iso(r["created_at"])} for r in rows]}


def _signup(signup_id: uuid.UUID) -> dict:
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM staff_signups WHERE signup_id = %s", (str(signup_id),)).fetchone()
    if row is None:
        raise GateError(ErrorCode.NOT_FOUND, "staff_signup_not_found", message="가입 신청을 찾을 수 없습니다. 이미 처리되었을 수 있습니다.")
    return row


def _kc_fail(request: Request, action: str, exc: Exception):
    reason = str(exc) if isinstance(exc, keycloak_admin.KeycloakAdminError) else "identity_unavailable"
    audit.deny(request, f"{action}:{reason}", action=action)
    raise GateError(ErrorCode.INTERNAL_ERROR, reason, message="계정 처리에 실패했습니다. 잠시 후 다시 시도해 주세요.")


@router.post("/staff-signups/{signup_id}/approve")
def approve_staff_signup(signup_id: uuid.UUID, request: Request,
                         principal: Principal = Depends(require("data_admin")), _csrf: None = Depends(require_csrf)):
    row = _signup(signup_id)
    user_id, role = str(row["user_id"]), row["requested_role"]
    try:
        keycloak_admin.approve_staff(user_id, role)
    except (keycloak_admin.KeycloakAdminError, httpx.HTTPError) as exc:
        _kc_fail(request, "staff_signup.approve", exc)
    try:
        with db.connection() as conn:
            done = conn.execute("SELECT * FROM approve_staff_signup(%s::uuid, %s::uuid)",
                                (str(signup_id), principal.user_id)).fetchone()
            text = f"{row['name']}({done['username']}) 님이 {ROLE_KO[role]}({done['pseudo_id']})로 승인되었습니다. 승인: {principal.pseudo_id}"
            notify.to_role(conn, "data_admin", "staff_signup_approved", "직원 가입 승인", text, "staff_signups",
                           exclude=principal.user_id)
            if role == "approver":
                notify.to_role(conn, "approver", "staff_signup_approved", "새 승인 담당자", text, None, exclude=user_id)
    except Exception:
        keycloak_admin.revert_staff(user_id, role)
        audit.deny(request, "staff_signup.approve:db_failed", action="staff_signup.approve")
        raise GateError(ErrorCode.INTERNAL_ERROR, "staff_signup_db_failed", message="승인을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.")
    audit.allow(request, action="staff_signup.approve", target_type="staff", target_id=done["pseudo_id"], reason=role)
    return {"status": "approved", "pseudo_id": done["pseudo_id"], "role": role, "username": done["username"]}


@router.post("/staff-signups/{signup_id}/reject")
def reject_staff_signup(signup_id: uuid.UUID, request: Request,
                        principal: Principal = Depends(require("data_admin")), _csrf: None = Depends(require_csrf)):
    row = _signup(signup_id)
    try:
        keycloak_admin.delete_pending_staff(str(row["user_id"]))
    except (keycloak_admin.KeycloakAdminError, httpx.HTTPError) as exc:
        _kc_fail(request, "staff_signup.reject", exc)
    with db.connection() as conn:
        conn.execute("DELETE FROM staff_signups WHERE signup_id = %s", (str(signup_id),))
    audit.allow(request, action="staff_signup.reject", target_type="staff_signup", target_id=str(signup_id),
                reason=row["requested_role"])
    return {"status": "rejected"}
