"""회원 Keycloak 계정 정리 (탈퇴 확정 후).

internal-admin client(service account, realm-management 의 view-users·manage-users)로 Keycloak 관리 API 를 부른다.
- logout(user_id): 탈퇴 확정 즉시 그 회원의 Keycloak 세션을 끊는다.
- delete_member(user_id): 안내 기간이 끝난 계정을 지운다. 지우기 전에 realm 역할이 member 뿐인지 확인한다
  (manage-users 는 직원 계정도 지울 수 있으므로 코드에서 회원 계정만 지우도록 막는다).
비밀값(client secret, 토큰)은 로그에 남기지 않는다.
"""
import httpx

from .auth.oidc import discovery
from .config import get_settings

STAFF_ROLES = {"counselor", "data_admin", "approver"}


class KeycloakAdminError(Exception):
    """사유 코드만 담는다."""


def enabled() -> bool:
    return bool(get_settings().kc_admin_client_secret)


def _base() -> str:
    s = get_settings()
    # OIDC_DISCOVERY_URL = http://keycloak:8080/realms/matchmaking/.well-known/... → 관리 API 도 같은 내부 주소
    root = s.oidc_discovery_url.split("/realms/")[0]
    return f"{root}/admin/realms/{s.kc_realm}"


def _token() -> str:
    s = get_settings()
    resp = httpx.post(discovery()["token_endpoint"], data={"grant_type": "client_credentials"},
                      auth=(s.kc_admin_client_id, s.kc_admin_client_secret), timeout=5)
    if resp.status_code != 200:
        raise KeycloakAdminError("admin_token_failed")
    return resp.json()["access_token"]


def _realm_roles(client: httpx.Client, user_id: str) -> set[str] | None:
    resp = client.get(f"{_base()}/users/{user_id}/role-mappings/realm/composite")   # 유효 역할 (기본 역할 포함)
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise KeycloakAdminError("role_lookup_failed")
    return {r["name"] for r in resp.json()}


def _client() -> httpx.Client:
    return httpx.Client(headers={"Authorization": f"Bearer {_token()}"}, timeout=5)


def logout(user_id: str) -> None:
    """그 계정의 모든 Keycloak 세션 종료. 계정이 없으면 무시."""
    with _client() as c:
        resp = c.post(f"{_base()}/users/{user_id}/logout")
    if resp.status_code not in (204, 404):
        raise KeycloakAdminError("logout_failed")


def delete_member(user_id: str) -> str:
    """회원 계정만 삭제. 돌려주는 값: deleted / not_found. 직원 역할이 있거나 member 역할이 없으면 거부."""
    with _client() as c:
        roles = _realm_roles(c, user_id)
        if roles is None:
            return "not_found"
        if "member" not in roles or roles & STAFF_ROLES:
            raise KeycloakAdminError("not_member_account")
        resp = c.delete(f"{_base()}/users/{user_id}")
    if resp.status_code == 404:
        return "not_found"
    if resp.status_code != 204:
        raise KeycloakAdminError("delete_failed")
    return "deleted"
