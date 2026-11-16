"""회원 Keycloak 계정 정리 (탈퇴 확정 후).

internal-admin client(service account, realm-management 의 view-users·manage-users)로 Keycloak 관리 API 를 부른다.
- logout(user_id): 탈퇴 확정 즉시 그 회원의 Keycloak 세션을 끊는다.
- create_member(...): 이음 가입 폼으로 새 회원 계정을 만든다. member 역할은 "members" 그룹으로만 준다
  (역할 직접 부여 권한 없이 manage-users 만으로 처리). 만든 뒤 유효 역할이 member 하나인지 다시 확인한다.
- delete_member(user_id): 안내 기간이 끝난 계정을 지운다. 지우기 전에 realm 역할이 member 뿐인지 확인한다
  (manage-users 는 직원 계정도 지울 수 있으므로 코드에서 회원 계정만 지우도록 막는다).
비밀값(client secret, 토큰)은 로그에 남기지 않는다.
"""
import uuid

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


MEMBER_GROUP = "/members"


def create_member(username: str, password: str, email: str) -> str:
    """회원 계정 생성 → Keycloak user id(sub). 비밀번호는 Keycloak 에만 저장하고 어디에도 남기지 않는다.
    사유 코드: account_exists(아이디·이메일 중복) / password_policy / account_invalid / create_failed / member_role_missing"""
    rep = {"username": username, "enabled": True, "email": email, "emailVerified": True,
           # 프로필 확인 화면(VERIFY_PROFILE)이 뜨지 않도록 이름 칸을 채운다. 실명은 업무 DB 에만 둔다
           "firstName": "회원", "lastName": username, "groups": [MEMBER_GROUP],
           "credentials": [{"type": "password", "value": password, "temporary": False}]}
    with _client() as c:
        resp = c.post(f"{_base()}/users", json=rep)
        if resp.status_code == 409:
            raise KeycloakAdminError("account_exists")
        if resp.status_code == 400:
            try:
                message = str(resp.json().get("errorMessage", ""))
            except ValueError:
                message = ""
            raise KeycloakAdminError("password_policy" if message.startswith("invalidPassword") else "account_invalid")
        if resp.status_code != 201:
            raise KeycloakAdminError("create_failed")
        user_id = resp.headers.get("Location", "").rstrip("/").rsplit("/", 1)[-1]
        try:
            user_id = str(uuid.UUID(user_id))
        except ValueError:
            raise KeycloakAdminError("create_failed")
        roles = _realm_roles(c, user_id)
        if roles is None or "member" not in roles or roles & STAFF_ROLES:
            c.delete(f"{_base()}/users/{user_id}")
            raise KeycloakAdminError("member_role_missing")
    return user_id


def remove_new_member(user_id: str) -> None:
    """가입 처리 중 업무 DB 저장이 실패했을 때 방금 만든 계정을 되돌린다 (회원 계정만)."""
    try:
        delete_member(user_id)
    except (KeycloakAdminError, httpx.HTTPError):
        pass


# ---------------------------------------------------------------------------
# 직원 가입 신청: 비활성·역할 없음으로 만들고, 총관리자 승인 때 활성화 + 역할 그룹(counselors·approvers)
# ---------------------------------------------------------------------------
BUSINESS_ROLES = STAFF_ROLES | {"member"}
STAFF_GROUPS = {"counselor": "counselors", "approver": "approvers"}


def create_staff_pending(username: str, password: str, email: str, name: str) -> str:
    """승인 전 직원 계정 → Keycloak user id. 비활성이라 로그인할 수 없고 업무 역할도 없다."""
    rep = {"username": username, "enabled": False, "email": email, "emailVerified": True,
           "firstName": name, "lastName": "직원",
           "credentials": [{"type": "password", "value": password, "temporary": False}]}
    with _client() as c:
        resp = c.post(f"{_base()}/users", json=rep)
        if resp.status_code == 409:
            raise KeycloakAdminError("account_exists")
        if resp.status_code == 400:
            try:
                message = str(resp.json().get("errorMessage", ""))
            except ValueError:
                message = ""
            raise KeycloakAdminError("password_policy" if message.startswith("invalidPassword") else "account_invalid")
        if resp.status_code != 201:
            raise KeycloakAdminError("create_failed")
        user_id = resp.headers.get("Location", "").rstrip("/").rsplit("/", 1)[-1]
        try:
            user_id = str(uuid.UUID(user_id))
        except ValueError:
            raise KeycloakAdminError("create_failed")
        roles = _realm_roles(c, user_id)
        if roles is None or roles & BUSINESS_ROLES:
            c.delete(f"{_base()}/users/{user_id}")
            raise KeycloakAdminError("unexpected_roles")
    return user_id


def _group_id(c: httpx.Client, name: str) -> str:
    resp = c.get(f"{_base()}/groups", params={"search": name, "exact": "true"})
    if resp.status_code != 200:
        raise KeycloakAdminError("group_lookup_failed")
    for g in resp.json():
        if g.get("name") == name:
            return g["id"]
    raise KeycloakAdminError("group_missing")


def _set_enabled(c: httpx.Client, user_id: str, enabled: bool) -> None:
    # 일부만 보내면 사용자 프로필 값이 지워질 수 있어 전체 표현을 받아 enabled 만 바꿔 다시 보낸다
    rep = c.get(f"{_base()}/users/{user_id}")
    if rep.status_code != 200:
        raise KeycloakAdminError("user_lookup_failed")
    body = rep.json()
    body["enabled"] = enabled
    if c.put(f"{_base()}/users/{user_id}", json=body).status_code != 204:
        raise KeycloakAdminError("update_failed")


def approve_staff(user_id: str, role: str) -> None:
    """비활성 신청 계정만: 역할 그룹에 넣고 활성화한 뒤, 업무 역할이 요청 역할 하나인지 확인."""
    group = STAFF_GROUPS.get(role)
    if not group:
        raise KeycloakAdminError("role_not_allowed")
    with _client() as c:
        rep = c.get(f"{_base()}/users/{user_id}")
        if rep.status_code == 404:
            raise KeycloakAdminError("account_missing")
        if rep.status_code != 200:
            raise KeycloakAdminError("user_lookup_failed")
        if rep.json().get("enabled"):
            raise KeycloakAdminError("not_pending_account")
        if (_realm_roles(c, user_id) or set()) & BUSINESS_ROLES:
            raise KeycloakAdminError("not_pending_account")
        gid = _group_id(c, group)
        if c.put(f"{_base()}/users/{user_id}/groups/{gid}").status_code != 204:
            raise KeycloakAdminError("group_join_failed")
        _set_enabled(c, user_id, True)
        if (_realm_roles(c, user_id) or set()) & BUSINESS_ROLES != {role}:
            _revert(c, user_id, gid)
            raise KeycloakAdminError("unexpected_roles")


def _revert(c: httpx.Client, user_id: str, gid: str) -> None:
    c.delete(f"{_base()}/users/{user_id}/groups/{gid}")
    try:
        _set_enabled(c, user_id, False)
    except KeycloakAdminError:
        pass


def revert_staff(user_id: str, role: str) -> None:
    """승인 처리 중 업무 DB 등록이 실패하면 다시 비활성·역할 없음으로 되돌린다."""
    try:
        with _client() as c:
            _revert(c, user_id, _group_id(c, STAFF_GROUPS[role]))
    except (KeycloakAdminError, httpx.HTTPError, KeyError):
        pass


def delete_pending_staff(user_id: str) -> str:
    """거절: 비활성이고 업무 역할이 없는 신청 계정만 삭제. 돌려주는 값: deleted / not_found."""
    with _client() as c:
        rep = c.get(f"{_base()}/users/{user_id}")
        if rep.status_code == 404:
            return "not_found"
        if rep.status_code != 200:
            raise KeycloakAdminError("user_lookup_failed")
        if rep.json().get("enabled") or (_realm_roles(c, user_id) or set()) & BUSINESS_ROLES:
            raise KeycloakAdminError("not_pending_account")
        resp = c.delete(f"{_base()}/users/{user_id}")
    if resp.status_code not in (204, 404):
        raise KeycloakAdminError("delete_failed")
    return "deleted"
