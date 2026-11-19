"""Keycloak 로그인·관리 이벤트를 감사 로그(→ Wazuh)로 옮긴다.

Keycloak 은 realm 이벤트(로그인 실패 등)와 관리 이벤트(역할·그룹·사용자 변경)를 자체 DB 에 저장한다
(realm-setup.sh 가 켬). internal-api 가 internal-admin service account(view-events)로 주기적으로 읽어
공통 형식 감사 기록으로 남긴다 → Wazuh 규칙 100180~100183 (로그인 실패·반복 실패·잠금·역할 변경).

- 남기는 값: 이벤트 종류, 오류 코드, 계정 아이디(로그인 이름), client, Keycloak 사용자 UUID, 관리 대상 경로.
  비밀번호·토큰·IP 주소는 남기지 않는다.
- 이 앱(internal-admin)이 회원가입·직원 승인으로 만든 관리 이벤트는 actor=svc:internal-admin 으로 구분한다.
- 실패해도 다른 기능에 영향 없음 (다음 주기에 다시 시도).
"""
import logging
import threading
import time
import uuid

import httpx

from . import audit, keycloak_admin

_log = logging.getLogger("internal-api.keycloak-events")
_stop = threading.Event()
_state = {"since_ms": None, "seen": set()}

LOGIN_TYPES = ("LOGIN_ERROR", "CODE_TO_TOKEN_ERROR", "REFRESH_TOKEN_ERROR", "LOGIN")
ROLE_RESOURCES = {"REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING", "GROUP_MEMBERSHIP", "REALM_ROLE", "CLIENT_ROLE",
                  "GROUP", "USER", "CLIENT", "REALM", "AUTH_FLOW", "AUTH_EXECUTION"}


def _short(value, n=128):
    return None if value is None else str(value)[:n]


def _record_login(e: dict) -> None:
    kind = e.get("type", "")
    details = e.get("details") or {}
    failed = kind.endswith("_ERROR")
    audit.writer().record(
        trace_id=uuid.uuid4().hex, action="keycloak." + kind.lower(), result="deny" if failed else "allow",
        actor=_short(details.get("username") or e.get("userId") or "unknown"), role=None,
        target_type="client", target_id=_short(e.get("clientId")),
        reason=_short(e.get("error") or ("login_ok" if not failed else "error")))


def _record_admin(e: dict, own_client_ids: set[str]) -> None:
    auth = e.get("authDetails") or {}
    actor = auth.get("userId") or "unknown"
    if auth.get("clientId") in own_client_ids:
        actor = "svc:" + auth["clientId"]
    op, res = e.get("operationType", "ACTION"), e.get("resourceType", "UNKNOWN")
    audit.writer().record(
        trace_id=uuid.uuid4().hex, action="keycloak.admin_event", result="allow", actor=_short(actor),
        role=None, target_type=_short(res.lower(), 32), target_id=_short(e.get("resourcePath")),
        reason=_short(f"{op}_{res}".lower()))


def poll_once(client: httpx.Client | None = None) -> int:
    """마지막으로 읽은 시각 이후 이벤트를 감사 기록으로 옮긴다. 옮긴 개수를 돌려준다."""
    if not keycloak_admin.enabled():
        return 0
    now_ms = int(time.time() * 1000)
    since = _state["since_ms"] or now_ms - 5 * 60 * 1000          # 처음 시작: 최근 5분부터
    params_date = time.strftime("%Y-%m-%d", time.gmtime(since / 1000 - 86400))
    own = {keycloak_admin.client_id()}
    moved = 0
    with (client or keycloak_admin.admin_client()) as c:
        base = keycloak_admin.realm_base()
        events = c.get(f"{base}/events", params={"dateFrom": params_date, "max": 500,
                                                  "type": list(LOGIN_TYPES)}).json()
        admin = c.get(f"{base}/admin-events", params={"dateFrom": params_date, "max": 500}).json()
    newest = since
    for e in sorted(events, key=lambda x: x.get("time", 0)):
        key = ("e", e.get("time"), e.get("type"), e.get("userId"), e.get("sessionId"))
        if e.get("time", 0) < since or key in _state["seen"]:
            continue
        if e.get("type") == "LOGIN" and (e.get("clientId") or "") not in ("internal-web",):
            continue   # 회원 정상 로그인은 양이 많아 남기지 않는다 (직원 로그인 성공만)
        _record_login(e)
        _state["seen"].add(key); moved += 1
        newest = max(newest, e.get("time", 0))
    for e in sorted(admin, key=lambda x: x.get("time", 0)):
        key = ("a", e.get("time"), e.get("resourcePath"), e.get("operationType"))
        if e.get("time", 0) < since or key in _state["seen"]:
            continue
        if e.get("resourceType") not in ROLE_RESOURCES:
            continue
        _record_admin(e, own)
        _state["seen"].add(key); moved += 1
        newest = max(newest, e.get("time", 0))
    _state["since_ms"] = max(since, newest - 1000)                 # 같은 ms 이벤트를 놓치지 않게 1초 겹쳐 읽는다
    if len(_state["seen"]) > 5000:
        _state["seen"] = set(list(_state["seen"])[-2000:])
    return moved


def _loop(interval: int) -> None:
    while not _stop.wait(interval):
        try:
            poll_once()
        except Exception as exc:   # Keycloak 일시 장애·권한 미설정: 다음 주기에 다시
            _log.warning("Keycloak 이벤트 수집 실패: %s", type(exc).__name__)


def start(interval: int = 30) -> None:
    if not keycloak_admin.enabled():
        return
    _stop.clear()
    threading.Thread(target=_loop, args=(interval,), name="keycloak-events", daemon=True).start()


def stop() -> None:
    _stop.set()
