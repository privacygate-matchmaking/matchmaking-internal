"""직원 로그인·로그아웃 (OIDC Authorization Code + PKCE, BFF 방식).

토큰은 브라우저에 주지 않는다. 브라우저에는 무작위 세션 ID 만 internal_session 쿠키로 준다.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from privacygate.policy import STAFF_ROLES, Principal
from privacygate.tokens import code_challenge_s256, new_code_verifier, random_token, same, token_hash

from .. import audit, db
from ..auth import oidc
from ..auth.session import current_principal, require_csrf
from ..config import SESSION_COOKIE, get_settings

router = APIRouter(prefix="/auth", tags=["auth"])

LOGIN_COOKIE = "internal_login"   # 로그인을 시작한 브라우저와 콜백 브라우저가 같은지 확인
LOGIN_TTL = timedelta(minutes=10)


@router.get("/login")
def login(request: Request):
    state, nonce, binding = random_token(), random_token(), random_token()
    verifier = new_code_verifier()
    with db.connection() as conn:
        conn.execute("DELETE FROM login_flows WHERE expires_at < now()")
        conn.execute(
            """INSERT INTO login_flows (state_hash, binding_hash, nonce, code_verifier, expires_at)
               VALUES (%s, %s, %s, %s, %s)""",
            (token_hash(state), token_hash(binding), nonce, verifier, datetime.now(timezone.utc) + LOGIN_TTL),
        )
    resp = RedirectResponse(oidc.authorization_url(state, nonce, code_challenge_s256(verifier)), status_code=302)
    resp.set_cookie(LOGIN_COOKIE, binding, max_age=int(LOGIN_TTL.total_seconds()), path="/auth",
                    httponly=True, secure=get_settings().cookie_secure, samesite="lax")
    return resp


def _fail(request: Request, reason: str) -> RedirectResponse:
    audit.deny(request, reason, action="login")
    resp = RedirectResponse("/?login=failed", status_code=302)
    resp.delete_cookie(LOGIN_COOKIE, path="/auth")
    return resp


@router.get("/callback")
def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    if error or not code or not state:
        return _fail(request, "idp_error" if error else "missing_params")

    with db.connection() as conn:
        flow = conn.execute(
            """DELETE FROM login_flows WHERE state_hash = %s
               RETURNING binding_hash, nonce, code_verifier, expires_at""",
            (token_hash(state),),
        ).fetchone()                                     # 한 번 쓰면 삭제 (재사용 방지)
    if flow is None:
        return _fail(request, "unknown_state")
    if flow["expires_at"] < datetime.now(timezone.utc):
        return _fail(request, "login_expired")
    binding = request.cookies.get(LOGIN_COOKIE)
    if not binding or not same(token_hash(binding), bytes(flow["binding_hash"])):
        return _fail(request, "browser_mismatch")

    try:
        tokens = oidc.exchange_code(code, flow["code_verifier"])
        claims = oidc.verify_id_token(tokens["id_token"], flow["nonce"])
    except oidc.OIDCError as exc:
        return _fail(request, str(exc))

    s = get_settings()
    now = datetime.now(timezone.utc)
    sid, csrf = random_token(), random_token()
    with db.connection() as conn:
        user = conn.execute("SELECT user_id, pseudo_id, role, active FROM users WHERE user_id = %s",
                            (claims["sub"],)).fetchone()
        if user is None or not user["active"] or user["role"] not in STAFF_ROLES:
            return _fail(request, "not_active_staff")   # 회원 계정은 내부 화면에 로그인할 수 없다
        conn.execute(
            """INSERT INTO sessions (session_hash, user_id, csrf_token, id_token, access_token,
                                     refresh_token, created_at, last_seen_at, absolute_expires_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (token_hash(sid), user["user_id"], csrf, tokens["id_token"], tokens["access_token"],
             tokens.get("refresh_token"), now, now,
             now + timedelta(seconds=s.session_max_seconds)),
        )
        conn.execute("DELETE FROM sessions WHERE absolute_expires_at < now()")

    request.state.principal = Principal(str(user["user_id"]), user["pseudo_id"], user["role"])
    audit.allow(request, action="login")

    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(LOGIN_COOKIE, path="/auth")
    # 로그인할 때마다 새 세션 ID 발급 → 세션 고정 공격 방지
    resp.set_cookie(SESSION_COOKIE, sid, path="/", httponly=True, secure=s.cookie_secure,
                    samesite="strict", max_age=s.session_max_seconds)
    return resp


@router.post("/logout")
def logout(request: Request, principal: Principal = Depends(current_principal),
           _csrf: None = Depends(require_csrf)):
    with db.connection() as conn:
        conn.execute("DELETE FROM sessions WHERE session_hash = %s", (request.state.session_hash,))
    audit.allow(request, action="logout")
    resp = JSONResponse({"logout_url": oidc.end_session_url(request.state.id_token)})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp
