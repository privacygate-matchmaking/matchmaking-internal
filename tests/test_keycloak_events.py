"""Keycloak 로그인·관리 이벤트 → 감사 로그 옮기기 시험 (Keycloak 없이 응답을 흉내 낸다)."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "internal-api"))
for k, v in {"DATABASE_URL": "postgresql://x/y", "OIDC_DISCOVERY_URL": "http://kc/realms/matchmaking/.well-known/openid-configuration",
             "OIDC_CLIENT_SECRET": "x", "APP_BASE_URL": "https://testserver"}.items():
    os.environ.setdefault(k, v)

import httpx

from app import audit, keycloak_admin, keycloak_events
from privacygate.audit import AuditWriter, verify_chain


class KeycloakEvents(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "internal-api.json"
        self.w = AuditWriter("internal-api", str(self.path))
        self._orig = (audit.writer, keycloak_admin.enabled, keycloak_admin.realm_base, keycloak_admin.client_id)
        audit.writer = lambda: self.w
        keycloak_admin.enabled = lambda: True
        keycloak_admin.realm_base = lambda: "http://kc/admin/realms/matchmaking"
        keycloak_admin.client_id = lambda: "internal-admin"
        keycloak_events._state.update(since_ms=None, seen=set())
        t = int(time.time() * 1000)
        self.events = [
            {"time": t - 3000, "type": "LOGIN_ERROR", "clientId": "internal-web", "userId": "u1", "error": "invalid_user_credentials",
             "details": {"username": "counselor_a", "auth_method": "openid-connect"}, "ipAddress": "10.0.0.9"},
            {"time": t - 2000, "type": "LOGIN", "clientId": "external-web", "userId": "m1", "details": {"username": "member_001"}},
            {"time": t - 1000, "type": "LOGIN", "clientId": "internal-web", "userId": "u2", "details": {"username": "data_admin"}},
        ]
        self.admin = [
            {"time": t - 1500, "operationType": "CREATE", "resourceType": "REALM_ROLE_MAPPING",
             "resourcePath": "users/u9/role-mappings/realm", "authDetails": {"userId": "admin-uuid", "clientId": "security-admin-console"}},
            {"time": t - 1200, "operationType": "UPDATE", "resourceType": "USER", "resourcePath": "users/u7",
             "authDetails": {"userId": "svc-uuid", "clientId": "internal-admin"}},
        ]

    def tearDown(self):
        audit.writer, keycloak_admin.enabled, keycloak_admin.realm_base, keycloak_admin.client_id = self._orig

    def client(self):
        def handler(req):
            if req.url.path.endswith("/admin-events"):
                return httpx.Response(200, json=self.admin)
            return httpx.Response(200, json=self.events)
        return httpx.Client(transport=httpx.MockTransport(handler))

    def lines(self):
        return [json.loads(l) for l in self.path.read_text().splitlines()]

    def test_moves_failures_staff_logins_and_role_changes(self):
        self.assertEqual(keycloak_events.poll_once(self.client()), 4)    # 회원 정상 로그인은 제외
        got = {(e["action"], e["reason"], e["actor"]) for e in self.lines()}
        self.assertIn(("keycloak.login_error", "invalid_user_credentials", "counselor_a"), got)
        self.assertIn(("keycloak.login", "login_ok", "data_admin"), got)
        self.assertIn(("keycloak.admin_event", "create_realm_role_mapping", "admin-uuid"), got)
        self.assertIn(("keycloak.admin_event", "update_user", "svc:internal-admin"), got)
        raw = self.path.read_text()
        self.assertNotIn("10.0.0.9", raw)          # IP 는 남기지 않음
        self.assertNotIn("member_001", raw)
        self.assertEqual(verify_chain(raw.splitlines()), [])

    def test_no_duplicates_on_next_poll(self):
        keycloak_events.poll_once(self.client())
        self.assertEqual(keycloak_events.poll_once(self.client()), 0)

    def test_disabled_without_admin_client(self):
        keycloak_admin.enabled = lambda: False
        self.assertEqual(keycloak_events.poll_once(self.client()), 0)


if __name__ == "__main__":
    unittest.main()
