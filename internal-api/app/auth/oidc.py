"""Keycloak OIDC: discovery, 토큰 교환, ID 토큰 검증.

컨테이너는 keycloak:8080 으로 discovery·토큰·JWKS 에 접근하고(backchannel),
브라우저는 KC_HOSTNAME(localhost:8081) 으로 로그인 화면에 간다.
토큰의 iss 는 브라우저 주소 기준이므로 discovery 의 issuer 값으로 검증한다.
"""
import threading
import time
from urllib.parse import urlencode

import httpx
import jwt
from privacygate.web import ServiceTokenVerifier

from ..config import get_settings

_TTL = 3600
_lock = threading.Lock()
_cache: dict = {"at": 0.0, "doc": None, "jwks": None, "svc": None}


class OIDCError(Exception):
    """사유 코드만 담는다 (토큰 원문은 담지 않음)."""


def discovery() -> dict:
    with _lock:
        if _cache["doc"] is None or time.time() - _cache["at"] > _TTL:
            resp = httpx.get(get_settings().oidc_discovery_url, timeout=5)
            resp.raise_for_status()
            doc = resp.json()
            _cache.update(at=time.time(), doc=doc, jwks=jwt.PyJWKClient(doc["jwks_uri"], cache_keys=True),
                          svc=ServiceTokenVerifier(doc["jwks_uri"], doc["issuer"], get_settings().api_audience))
        return _cache["doc"]


def service_verifier() -> ServiceTokenVerifier:
    """서버 간 API(/api/internal/*) 의 서비스 토큰 검증기."""
    discovery()
    return _cache["svc"]


def authorization_url(state: str, nonce: str, code_challenge: str) -> str:
    s = get_settings()
    params = {"response_type": "code", "client_id": s.oidc_client_id, "redirect_uri": s.redirect_uri,
              "scope": "openid", "state": state, "nonce": nonce,
              "code_challenge": code_challenge, "code_challenge_method": "S256"}
    return f"{discovery()['authorization_endpoint']}?{urlencode(params)}"


def exchange_code(code: str, code_verifier: str) -> dict:
    s = get_settings()
    resp = httpx.post(
        discovery()["token_endpoint"],
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": s.redirect_uri,
              "code_verifier": code_verifier},
        auth=(s.oidc_client_id, s.oidc_client_secret),
        timeout=5,
    )
    if resp.status_code != 200:
        raise OIDCError("token_exchange_failed")
    tokens = resp.json()
    if "id_token" not in tokens:
        raise OIDCError("no_id_token")
    return tokens


def verify_id_token(id_token: str, expected_nonce: str) -> dict:
    s = get_settings()
    issuer = discovery()["issuer"]
    try:
        key = _cache["jwks"].get_signing_key_from_jwt(id_token)
        claims = jwt.decode(id_token, key.key, algorithms=["RS256"], audience=s.oidc_client_id,
                            issuer=issuer,
                            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]}, leeway=30)
    except jwt.PyJWTError as exc:
        raise OIDCError("id_token_invalid") from exc
    if claims.get("nonce") != expected_nonce:
        raise OIDCError("nonce_mismatch")
    if claims.get("azp", s.oidc_client_id) != s.oidc_client_id:
        raise OIDCError("azp_mismatch")
    return claims


def end_session_url(id_token: str) -> str:
    s = get_settings()
    params = {"id_token_hint": id_token, "post_logout_redirect_uri": f"{s.app_base_url}/"}
    return f"{discovery()['end_session_endpoint']}?{urlencode(params)}"


def refresh_tokens(refresh_token: str) -> dict:
    """서버에 보관한 refresh token 으로 access token 을 갱신한다 (브라우저는 관여하지 않음)."""
    s = get_settings()
    resp = httpx.post(
        discovery()["token_endpoint"],
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        auth=(s.oidc_client_id, s.oidc_client_secret),
        timeout=5,
    )
    if resp.status_code != 200:
        raise OIDCError("token_refresh_failed")
    return resp.json()
