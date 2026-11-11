"""internal-api → transfer-api 호출.

- 직원 화면의 반출 업무는 서버에 보관한 직원 access token(aud=transfer-api, azp=internal-web)을 붙여 전달한다.
  만료가 가까우면 refresh token 으로 갱신하고 세션에 저장한다. 토큰은 브라우저에 주지 않는다.
- 추적 ID(X-Trace-Id)를 함께 보내 중계 감사 로그와 잇는다.
"""
import time

import httpx
import jwt
from fastapi import Request
from fastapi.responses import JSONResponse, Response
from privacygate.errors import ErrorCode, GateError

from . import db
from .auth import oidc
from .config import get_settings

_SKEW = 30


def _exp(token: str) -> float:
    # 만료 시각만 읽는다 (서명 검증은 받는 쪽 transfer-api 가 한다)
    return float(jwt.decode(token, options={"verify_signature": False}).get("exp", 0))


def staff_access_token(request: Request) -> str:
    sid_hash = request.state.session_hash
    with db.connection() as conn:
        row = conn.execute("SELECT access_token, refresh_token FROM sessions WHERE session_hash = %s",
                           (sid_hash,)).fetchone()
    if row is None:
        raise GateError(ErrorCode.AUTH_REQUIRED, "unknown_session")
    token = row["access_token"]
    if _exp(token) - _SKEW > time.time():
        return token
    if not row["refresh_token"]:
        raise GateError(ErrorCode.AUTH_REQUIRED, "access_token_expired")
    try:
        tokens = oidc.refresh_tokens(row["refresh_token"])
    except oidc.OIDCError as exc:
        raise GateError(ErrorCode.AUTH_REQUIRED, "token_refresh_failed") from exc
    with db.connection() as conn:
        conn.execute("UPDATE sessions SET access_token = %s, refresh_token = COALESCE(%s, refresh_token) "
                     "WHERE session_hash = %s",
                     (tokens["access_token"], tokens.get("refresh_token"), sid_hash))
    return tokens["access_token"]


def call(request: Request, method: str, path: str, *, json: dict | None = None,
         params: dict | None = None, files: dict | None = None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {staff_access_token(request)}",
               "X-Trace-Id": request.state.trace_id}
    try:
        return httpx.request(method, f"{get_settings().transfer_api_url}{path}", headers=headers,
                             json=json, params=params, files=files, timeout=15)
    except httpx.HTTPError as exc:
        raise GateError(ErrorCode.INTERNAL_ERROR, "transfer_unreachable") from exc


def relay(resp: httpx.Response) -> Response:
    """중계 응답(성공·공통 오류 형식)을 그대로 돌려준다.
    단, 중계가 직원 토큰을 거절한 401 은 브라우저 세션 만료가 아니므로 그대로 넘기지 않는다
    (넘기면 화면이 로그인 화면으로 돌아간다). 내부 오류로 바꾸고 사유를 감사 로그에 남긴다."""
    if resp.status_code == 401:
        raise GateError(ErrorCode.INTERNAL_ERROR, "transfer_rejected_staff_token")
    ctype = resp.headers.get("content-type", "")
    if ctype.startswith("application/json"):
        return JSONResponse(resp.json(), status_code=resp.status_code)
    return Response(resp.content, status_code=resp.status_code, media_type=ctype or None)
