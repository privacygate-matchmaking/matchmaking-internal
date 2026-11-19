








from datetime import datetime, timezone

from fastapi import Depends, Request
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import STAFF_ROLES, Principal, Role, role_from_claims
from privacygate.session_rules import csrf_problem, session_problem
from privacygate.tokens import token_hash
from privacygate.web import role_guard, service_guard

from .. import db, security
from ..config import SESSION_COOKIE, get_settings
from .oidc import service_verifier, staff_relay_verifier


def session_principal(request: Request) -> Principal:
    """세션 확인만 (유효·활성 직원). 임시 잠금 여부는 request.state.locked_until 에 담고 막지 않는다 — 로그아웃용."""
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        raise GateError(ErrorCode.AUTH_REQUIRED, "no_session")
    s = get_settings()
    now = datetime.now(timezone.utc)
    sid_hash = token_hash(sid)
    with db.connection() as conn:
        row = conn.execute(
            """SELECT se.user_id, se.csrf_token, se.id_token, se.last_seen_at, se.absolute_expires_at,
                      u.pseudo_id, u.role, u.active
                 FROM sessions se JOIN users u ON u.user_id = se.user_id
                WHERE se.session_hash = %s""",
            (sid_hash,),
        ).fetchone()
        if row is None:
            raise GateError(ErrorCode.AUTH_REQUIRED, "unknown_session")
        problem = session_problem(now, row["last_seen_at"], row["absolute_expires_at"], s.session_idle_seconds)
        if problem is None and (not row["active"] or row["role"] not in STAFF_ROLES):
            problem = "not_active_staff"
        if problem:
            conn.execute("DELETE FROM sessions WHERE session_hash = %s", (sid_hash,))
            conn.commit()
            raise GateError(ErrorCode.AUTH_REQUIRED, problem)
        conn.execute("UPDATE sessions SET last_seen_at = %s WHERE session_hash = %s", (now, sid_hash))
        until = security.locked_until(conn, row["user_id"])

    principal = Principal(user_id=str(row["user_id"]), pseudo_id=row["pseudo_id"], role=row["role"])
    request.state.principal = principal
    request.state.csrf_token = row["csrf_token"]
    request.state.id_token = row["id_token"]
    request.state.session_hash = sid_hash
    request.state.locked_until = until
    return principal


def current_principal(request: Request, principal: Principal = Depends(session_principal)) -> Principal:
    """업무 요청: 세션 확인 + 자동 임시 잠금 중이면 거부 (세션은 두고, 잠금이 풀리면 그대로 이어 쓴다)."""
    until = getattr(request.state, "locked_until", None)
    if until:
        raise GateError(ErrorCode.ACCESS_DENIED, "account_temporarily_locked", security.lock_message(until))
    return principal


require = role_guard(current_principal)


def require_csrf(request: Request, principal: Principal = Depends(current_principal)) -> None:
    check_csrf(request)


def check_csrf(request: Request) -> None:
    problem = csrf_problem(expected_token=request.state.csrf_token,
                           sent_token=request.headers.get("X-CSRF-Token"),
                           origin_header=request.headers.get("Origin"),
                           app_base_url=get_settings().app_base_url)
    if problem:
        raise GateError(ErrorCode.ACCESS_DENIED, problem)


def require_service(*clients: str):
    return service_guard(service_verifier, *clients)


USER_TOKEN_HEADER = "X-User-Token"
_from_transfer = service_guard(service_verifier, "transfer-api")


def _member_claims(request: Request) -> dict:
    token = request.headers.get(USER_TOKEN_HEADER)
    if not token:
        raise GateError(ErrorCode.AUTH_REQUIRED, "member_token_missing")
    claims = service_verifier().verify(token)
    if claims.get("azp") != "external-web" or role_from_claims(claims) != Role.MEMBER.value:
        raise GateError(ErrorCode.ACCESS_DENIED, "not_member_token")
    return claims


def member_token_via_transfer(request: Request, _svc: dict = Depends(_from_transfer)) -> str:


    sub = _member_claims(request)["sub"]
    request.state.principal = Principal(user_id=sub, pseudo_id="-", role=Role.MEMBER.value)
    return sub


def member_via_transfer(request: Request, _svc: dict = Depends(_from_transfer)) -> Principal:





    claims = _member_claims(request)
    with db.connection() as conn:
        row = conn.execute("SELECT user_id, pseudo_id, role, active FROM users WHERE user_id = %s",
                           (claims["sub"],)).fetchone()
        if row is None or not row["active"] or row["role"] != Role.MEMBER.value:
            raise GateError(ErrorCode.ACCESS_DENIED, "not_active_member")
        security.ensure_not_locked(conn, row["user_id"])
    principal = Principal(user_id=str(row["user_id"]), pseudo_id=row["pseudo_id"], role=row["role"])
    request.state.principal = principal
    return principal


def staff_via_transfer(request: Request, _svc: dict = Depends(_from_transfer)) -> Principal:

    token = request.headers.get(USER_TOKEN_HEADER, '')
    if not token:
        raise GateError(ErrorCode.AUTH_REQUIRED, 'staff_token_missing')
    claims = staff_relay_verifier().verify(token)
    if claims.get('azp') != 'internal-web' or role_from_claims(claims) != Role.COUNSELOR.value:
        raise GateError(ErrorCode.ACCESS_DENIED, 'not_counselor_token')
    with db.connection() as conn:
        row = conn.execute('SELECT user_id, pseudo_id, role, active FROM users WHERE user_id = %s',
                           (claims.get('sub'),)).fetchone()
        if not row or not row['active'] or row['role'] != Role.COUNSELOR.value:
            raise GateError(ErrorCode.ACCESS_DENIED, 'not_active_counselor')
        security.ensure_not_locked(conn, row['user_id'])
    principal = Principal(str(row['user_id']), row['pseudo_id'], row['role'])
    request.state.principal = principal
    return principal


def staff_or_admin_via_transfer(request: Request, _svc: dict = Depends(_from_transfer)) -> Principal:
    """중계가 직원 토큰을 함께 보낸 요청 중 상담 직원·총관리자 (회원 이용권 조회 범위 확인용)."""
    token = request.headers.get(USER_TOKEN_HEADER, '')
    if not token:
        raise GateError(ErrorCode.AUTH_REQUIRED, 'staff_token_missing')
    claims = staff_relay_verifier().verify(token)
    allowed = (Role.COUNSELOR.value, Role.DATA_ADMIN.value)
    if claims.get('azp') != 'internal-web' or role_from_claims(claims) not in allowed:
        raise GateError(ErrorCode.ACCESS_DENIED, 'not_staff_token')
    with db.connection() as conn:
        row = conn.execute('SELECT user_id, pseudo_id, role, active FROM users WHERE user_id = %s',
                           (claims.get('sub'),)).fetchone()
        if not row or not row['active'] or row['role'] not in allowed:
            raise GateError(ErrorCode.ACCESS_DENIED, 'not_active_staff')
        security.ensure_not_locked(conn, row['user_id'])
    principal = Principal(str(row['user_id']), row['pseudo_id'], row['role'])
    request.state.principal = principal
    return principal
