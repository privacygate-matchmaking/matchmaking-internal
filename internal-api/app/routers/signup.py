"""이음 회원가입 (외부 가입 폼 → external-api → transfer-api → internal-api). ※ 명세 외 추가

- 호출자: transfer-api 서비스 토큰만 (로그인 전이므로 회원 토큰 없음).
- 순서: 입력 검사 → Keycloak 계정 생성(members 그룹 = member 역할) → 업무 DB register_member()
  (users·members 저장, 담당 회원이 가장 적은 상담 직원 자동 배정·알림) → 실패하면 Keycloak 계정을 되돌린다.
- 비밀번호는 Keycloak 에만 저장한다. 업무 DB·감사 로그·알림에 남기지 않는다.
- 응답에는 가입 완료 여부만 담는다 (회원 코드·담당자 등 내부 값은 돌려주지 않음).
"""
import re
from datetime import date, datetime, timedelta, timezone
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, Request
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import Principal, Role
from pydantic import BaseModel, ConfigDict, Field

from .. import audit, db, keycloak_admin
from ..auth.session import require_service

router = APIRouter(prefix="/api")

USERNAME = re.compile(r"^[a-z][a-z0-9_]{3,19}$")
PHONE = re.compile(r"^01[016789]-?\d{3,4}-?\d{4}$")
EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,24}$")
MIN_AGE = 19
CONSENT_VERSION = "2026-11"


class SignupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=4, max_length=20)
    password: str = Field(min_length=12, max_length=64)
    name: str = Field(min_length=1, max_length=30)
    gender: Literal["남", "여"]
    birth_date: date
    contact_phone: str = Field(max_length=20)
    contact_email: str = Field(max_length=200)
    education_level: Literal["고졸", "전문대졸", "4년제 대졸", "대학원졸"]
    job_group: str = Field(min_length=1, max_length=40)
    height_cm: int = Field(ge=120, le=230)
    weight_kg: int = Field(ge=30, le=200)
    introduction: str = Field(min_length=1, max_length=300)
    privacy_consent: Literal[True]
    consent_version: Literal["2026-11"]


def _bad(reason: str, message: str):
    raise GateError(ErrorCode.INVALID_REQUEST, reason, message=message)


def _age(birth: date, today: date) -> int:
    return today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))


def clean(body: SignupIn, today: date | None = None) -> dict:
    """형식 검사 후 저장할 값. 비밀번호는 돌려주지 않는다."""
    today = today or datetime.now(timezone(timedelta(hours=9))).date()
    if not USERNAME.match(body.username):
        _bad("username_invalid", "아이디는 영문 소문자로 시작하는 4~20자(영문 소문자·숫자·_)로 입력하세요.")
    if body.username.lower() in body.password.lower():
        _bad("password_contains_username", "비밀번호에 아이디를 넣을 수 없습니다.")
    if not body.password.strip() or body.password != body.password.strip():
        _bad("password_invalid", "비밀번호 앞뒤에 공백을 넣을 수 없습니다.")
    name = body.name.strip()
    if not name or any(ch in name for ch in "<>\r\n\t"):
        _bad("name_invalid", "이름을 확인하세요.")
    if body.birth_date > today or body.birth_date.year < 1900:
        _bad("birth_invalid", "생년월일을 확인하세요.")
    if _age(body.birth_date, today) < MIN_AGE:
        _bad("underage", f"만 {MIN_AGE}세 이상만 가입할 수 있습니다.")
    phone = body.contact_phone.strip()
    if not PHONE.match(phone):
        _bad("phone_invalid", "휴대전화 번호 형식(010-1234-5678)을 확인하세요.")
    digits = re.sub(r"\D", "", phone)
    email = body.contact_email.strip()
    if not EMAIL.match(email):
        _bad("email_invalid", "이메일 형식을 확인하세요.")
    job, intro = body.job_group.strip(), body.introduction.strip()
    if not job or any(ch in job for ch in "<>\r\n\t"):
        _bad("job_invalid", "직군을 입력하세요.")
    if not intro:
        _bad("introduction_required", "소개를 입력하세요.")
    return {"username": body.username, "name": name, "gender": body.gender, "birth_date": body.birth_date,
            "contact_phone": f"{digits[:3]}-{digits[3:-4]}-{digits[-4:]}", "contact_email": email,
            "education_level": body.education_level, "job_group": job,
            "height_cm": body.height_cm, "weight_kg": body.weight_kg, "introduction": intro}


KC_MESSAGES = {
    "account_exists": (ErrorCode.INVALID_STATE, "이미 사용 중인 아이디 또는 이메일입니다."),
    "password_policy": (ErrorCode.INVALID_REQUEST, "비밀번호는 12자 이상이며 아이디를 포함할 수 없습니다."),
    "account_invalid": (ErrorCode.INVALID_REQUEST, "입력한 계정 정보를 확인하세요."),
}


def save(conn, user_id: str, v: dict, consent_version: str) -> dict:
    """업무 DB 저장 (app_user 는 users·members INSERT 권한이 없어 SECURITY DEFINER 함수로만 만든다)."""
    return conn.execute(
        """SELECT member_id, pseudo_id, counselor_id FROM register_member(
               %(uid)s::uuid, %(username)s::text, %(name)s::text, %(gender)s::text, %(birth_date)s::date,
               %(contact_phone)s::text, %(contact_email)s::text, %(education_level)s::text, %(job_group)s::text,
               %(height_cm)s::smallint, %(weight_kg)s::smallint, %(introduction)s::text, %(consent)s::text)""",
        {**v, "uid": user_id, "consent": consent_version}).fetchone()


@router.post("/internal/member-signups", status_code=201)
def member_signup(body: SignupIn, request: Request, _svc: dict = Depends(require_service("transfer-api"))):
    values = clean(body)
    if not keycloak_admin.enabled():
        raise GateError(ErrorCode.INVALID_STATE, "signup_not_enabled", message="회원가입을 사용할 수 없습니다. 고객센터로 문의해 주세요.")
    try:
        user_id = keycloak_admin.create_member(body.username, body.password, values["contact_email"])
    except keycloak_admin.KeycloakAdminError as exc:
        reason = str(exc)
        audit.deny(request, f"signup:{reason}", action="member.signup")
        code, message = KC_MESSAGES.get(reason, (ErrorCode.INTERNAL_ERROR, "회원가입을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요."))
        raise GateError(code, reason, message=message)
    except httpx.HTTPError:
        audit.deny(request, "signup:identity_unavailable", action="member.signup")
        raise GateError(ErrorCode.INTERNAL_ERROR, "identity_unavailable", message="회원가입을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.")
    try:
        with db.connection() as conn:
            row = save(conn, user_id, values, body.consent_version)
    except Exception:
        keycloak_admin.remove_new_member(user_id)
        audit.deny(request, "signup:db_failed", action="member.signup")
        raise GateError(ErrorCode.INTERNAL_ERROR, "signup_db_failed", message="회원가입을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.")
    request.state.principal = Principal(user_id=user_id, pseudo_id=row["pseudo_id"], role=Role.MEMBER.value)
    audit.allow(request, action="member.signup", target_type="member", target_id=row["pseudo_id"],
                reason="assigned" if row["counselor_id"] else "unassigned")
    return {"status": "registered", "username": body.username}
