"""사후 대응(보안 사건·자동 임시 잠금·계정 정지) 검사 (실제 business-db + 시드 데이터 기준).

- 공격 ①: 상담 직원의 관리자 내보내기 3회 → 모두 403, 보안 사건 1건(3회), 15분 자동 잠금, 이후 모든 업무 요청 403
- 거부 2회까지는 잠그지 않음, 60초가 지난 신호는 세지 않음
- 감사 로그 파일·DB 기록이 실패해도(SIEM 수집 중단 상황) 차단·잠금은 그대로
- 총관리자 조치: 잠금 해제, 계정 정지(세션 삭제 → 401)·복구, 본인·총관리자 정지 거부, 회원 받은 자료 회수(중계 호출)
- 공격 ②: 중계가 알린 회원의 승인 외 자료 요청 → 사건, 3회면 잠금, 회원 상태(my-status) locked / suspended
- 사건 화면 API 는 총관리자만

로그인은 실제 세션 행을 만들어 쿠키로 보내고(잠금 확인 코드가 그대로 돈다), CSRF 만 의존성 바꿔치기로 건너뛴다.
Keycloak 관리 호출은 끈다 (실제 계정을 비활성으로 만들지 않음 — 결과 코드 keycloak_not_configured).
끝나면 잠금·신호·세션·알림을 지우고 계정을 복구하며, 시험 중 생긴 사건은 '오탐 · 자동 시험'으로 닫는다.

실행 (privacygate 폴더에서, 시드 데이터가 들어 있고 upgrade/014 를 적용한 상태):
  docker compose exec -T internal-api python - < ../matchmaking-internal/tests/test_security_response.py
"""
import contextlib
import logging
import os
import secrets
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone

os.environ["AUDIT_LOG_PATH"] = os.environ.get("TEST_AUDIT_LOG_PATH", "/tmp/test-security-audit.json")
sys.path.insert(0, os.getcwd())

try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None

COUNSELOR_A = "11111111-1111-4111-8111-111111111101"
DATA_ADMIN = "11111111-1111-4111-8111-111111111102"
APPROVER = "11111111-1111-4111-8111-111111111103"
COUNSELOR_B = "11111111-1111-4111-8111-111111111104"
MEMBER_B = "22222222-2222-4222-8222-222222222201"      # A-003 (member_b)


@unittest.skipIf(TestClient is None, "internal-api 컨테이너 안에서 실행")
class SecurityResponse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import audit, db, security
        from app.auth import session
        from app.config import SESSION_COOKIE, get_settings
        from app.main import app
        from privacygate.policy import Principal
        from privacygate.tokens import token_hash

        logging.getLogger("httpx").setLevel(logging.WARNING)
        db.open_pool(get_settings().database_url)
        cls.db, cls.app, cls.session, cls.security, cls.audit = db, app, session, security, audit
        cls.Principal, cls.cookie = Principal, SESSION_COOKIE
        cls.token_hash = staticmethod(token_hash)
        with db.connection() as conn:
            try:
                conn.execute("SELECT 1 FROM security_incidents LIMIT 1")
            except Exception:
                raise unittest.SkipTest("security_incidents 테이블이 없습니다. upgrade/014-security-response.sql 을 먼저 적용하세요")
            seeded = conn.execute("SELECT count(*) AS n FROM users WHERE user_id = ANY(%s) AND active",
                                  ([COUNSELOR_A, DATA_ADMIN, COUNSELOR_B, MEMBER_B],)).fetchone()["n"]
        if seeded != 4:
            raise unittest.SkipTest("시드 계정(counselor_a·b, data_admin, member_b)이 활성 상태가 아닙니다")
        app.dependency_overrides[session.require_csrf] = lambda: None
        # 실제 Keycloak 계정은 건드리지 않는다 (정지·복구 시험은 업무 DB 쪽만 확인)
        from app import keycloak_admin
        cls.keycloak_admin, cls._kc_enabled = keycloak_admin, keycloak_admin.enabled
        keycloak_admin.enabled = lambda: False
        cls.started = cls._db_now()

    @classmethod
    def tearDownClass(cls):
        cls.app.dependency_overrides.clear()
        cls.keycloak_admin.enabled = cls._kc_enabled
        cls._cleanup()
        with cls.db.connection() as conn:
            conn.execute("DELETE FROM notifications WHERE created_at >= %s", (cls.started,))
            conn.execute("""UPDATE security_incidents SET status = 'false_positive', note = '자동 시험 (test_security_response)'
                             WHERE first_seen_at >= %s""", (cls.started,))
        cls.db.close_pool()

    @classmethod
    def _cleanup(cls):
        ids = [COUNSELOR_A, COUNSELOR_B, APPROVER, MEMBER_B]
        with cls.db.connection() as conn:
            conn.execute("DELETE FROM account_locks WHERE user_id = ANY(%s)", (ids,))
            conn.execute("DELETE FROM security_signals WHERE user_id = ANY(%s)", (ids,))
            for uid in ids:
                if not conn.execute("SELECT active FROM users WHERE user_id = %s", (uid,)).fetchone()["active"]:
                    conn.execute("SELECT set_account_active(%s, true, %s)", (uid, DATA_ADMIN))
            conn.execute("DELETE FROM sessions WHERE csrf_token = 'test-security'")
        # 이전 시험에서 열린 사건과 합쳐지지 않게 한다
        with cls.db.connection() as conn:
            conn.execute("""UPDATE security_incidents SET status = 'false_positive', note = '자동 시험 (test_security_response)'
                             WHERE first_seen_at >= %s AND status IN ('new', 'reviewing')""", (cls.started if hasattr(cls, "started") else datetime.now(timezone.utc),))

    def setUp(self):
        self._cleanup()

    @classmethod
    def _db_now(cls):
        with cls.db.connection() as conn:
            return conn.execute("SELECT now() AS t").fetchone()["t"]

    # ---------- 도우미 ----------
    def login(self, user_id) -> TestClient:
        """실제 세션 행을 만든다 → current_principal(세션·활성·잠금 확인)이 그대로 돈다."""
        sid = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        with self.db.connection() as conn:
            conn.execute("""INSERT INTO sessions (session_hash, user_id, csrf_token, id_token, access_token, refresh_token,
                                                  created_at, last_seen_at, absolute_expires_at)
                            VALUES (%s, %s, 'test-security', 'id', 'access', NULL, %s, %s, %s)""",
                         (self.token_hash(sid), user_id, now, now, now + timedelta(hours=1)))
        c = TestClient(self.app, raise_server_exceptions=False)
        c.cookies.set(self.cookie, sid)
        return c

    @contextlib.contextmanager
    def as_member(self, user_id):
        p = self.Principal(user_id=user_id, pseudo_id="A-003", role="member")
        o = self.app.dependency_overrides
        o[self.session.member_token_via_transfer] = lambda: user_id
        o[self.session.member_via_transfer] = lambda: p
        try:
            yield TestClient(self.app, raise_server_exceptions=False)
        finally:
            o.pop(self.session.member_token_via_transfer, None)
            o.pop(self.session.member_via_transfer, None)

    def base_url(self):
        from app.config import get_settings
        return get_settings().app_base_url

    def reason_of(self, resp):
        return resp.json().get("error", {}).get("code")

    def incidents(self, user_id, kind=None):
        with self.db.connection() as conn:
            q = "SELECT * FROM security_incidents WHERE subject_user_id = %s AND first_seen_at >= %s"
            args = [user_id, self.started]
            if kind:
                q += " AND kind = %s"; args.append(kind)
            return conn.execute(q + " AND status IN ('new','reviewing') ORDER BY first_seen_at", args).fetchall()

    def exports_by(self, user_id):
        with self.db.connection() as conn:
            return conn.execute("SELECT count(*) AS n FROM member_exports WHERE created_by = %s AND created_at >= %s",
                                (user_id, self.started)).fetchone()["n"]

    # ---------- 공격 ① + 자동 임시 잠금 ----------
    def test_attack1_blocked_recorded_and_locked(self):
        before = self.exports_by(COUNSELOR_A)
        c = self.login(COUNSELOR_A)
        statuses = [c.post("/api/admin/member-exports").status_code for _ in range(3)]
        self.assertEqual(statuses, [403, 403, 403])
        self.assertEqual(self.exports_by(COUNSELOR_A), before)
        inc = self.incidents(COUNSELOR_A, "unauthorized_export")
        self.assertEqual(len(inc), 1)
        self.assertTrue(inc[0]["blocked"])
        self.assertEqual(inc[0]["occurrences"], 3)
        self.assertEqual(inc[0]["subject_code"], "A-C01")
        self.assertIsNotNone(inc[0]["auto_locked_until"])
        # 잠금 뒤에는 원래 허용된 요청도 막힌다
        r = c.get("/api/members")
        self.assertEqual(r.status_code, 403)
        self.assertIn("임시 잠겼습니다", r.json()["error"]["message"])
        self.assertEqual(c.post("/api/member-exports/%s/transfer-files" % uuid.uuid4()).status_code, 403)
        # 다른 직원은 영향 없음
        self.assertEqual(self.login(COUNSELOR_B).get("/api/members").status_code, 200)
        # 잠긴 상태에서도 로그아웃은 된다 (CSRF 확인은 그대로)
        from app.auth import oidc
        original = oidc.end_session_url
        oidc.end_session_url = lambda id_token: "https://keycloak.test/logout"
        try:
            self.assertEqual(c.post("/auth/logout").status_code, 403)          # CSRF 없음
            r = c.post("/auth/logout", headers={"X-CSRF-Token": "test-security", "Origin": self.base_url()})
            self.assertEqual(r.status_code, 200, r.text)
        finally:
            oidc.end_session_url = original
        self.assertEqual(c.get("/api/members").status_code, 401)
        # 총관리자 알림
        with self.db.connection() as conn:
            n = conn.execute("""SELECT count(*) AS n FROM notifications WHERE user_id = %s AND kind = 'security_incident'
                                 AND created_at >= %s""", (DATA_ADMIN, self.started)).fetchone()["n"]
        self.assertGreaterEqual(n, 2)   # 사건 + 자동 잠금

    def test_two_denials_do_not_lock_and_old_signals_expire(self):
        c = self.login(COUNSELOR_A)
        for _ in range(2):
            self.assertEqual(c.post("/api/admin/member-exports").status_code, 403)
        self.assertEqual(c.get("/api/members").status_code, 200)
        with self.db.connection() as conn:   # 2건이 61초 전에 있었던 것으로 바꾸면 다음 거부는 1건으로 센다
            conn.execute("DELETE FROM security_signals WHERE user_id = %s", (COUNSELOR_A,))
            for _ in range(2):
                conn.execute("INSERT INTO security_signals (user_id, kind, created_at) VALUES (%s, 'role_denied', now() - interval '61 seconds')",
                             (COUNSELOR_A,))
        self.assertEqual(c.post("/api/admin/member-exports").status_code, 403)
        self.assertEqual(c.get("/api/members").status_code, 200)

    def test_other_role_denials_also_lock(self):
        c = self.login(COUNSELOR_A)
        for path in ("/api/staff-signups", "/api/admin/security-incidents", "/api/admin/member-exports"):
            self.assertEqual(c.get(path).status_code, 403)
        self.assertEqual(c.get("/api/members").status_code, 403)
        inc = self.incidents(COUNSELOR_A, "repeated_denials")
        self.assertEqual(len(inc), 1)
        self.assertIsNotNone(inc[0]["auto_locked_until"])

    def test_blocking_does_not_depend_on_audit_shipping(self):
        """Wazuh 가 읽는 감사 파일·감사 DB 기록이 모두 실패해도 차단과 잠금은 그대로 (SIEM 장애 대비)."""
        w = self.audit.writer()
        path, insert = w.path, w.db_insert
        w.path = "/nonexistent-dir/audit.json"
        w.db_insert = lambda event: (_ for _ in ()).throw(RuntimeError("db down"))
        try:
            before = self.exports_by(COUNSELOR_A)
            c = self.login(COUNSELOR_A)
            self.assertEqual([c.post("/api/admin/member-exports").status_code for _ in range(3)], [403] * 3)
            self.assertEqual(c.get("/api/members").status_code, 403)
            self.assertEqual(self.exports_by(COUNSELOR_A), before)
        finally:
            w.path, w.db_insert = path, insert

    # ---------- 총관리자 조치 ----------
    def lock_counselor(self):
        c = self.login(COUNSELOR_A)
        for _ in range(3):
            c.post("/api/admin/member-exports")
        return c, str(self.incidents(COUNSELOR_A, "unauthorized_export")[0]["incident_id"])

    def test_admin_lists_and_unlocks(self):
        c, incident_id = self.lock_counselor()
        admin = self.login(DATA_ADMIN)
        items = admin.get("/api/admin/security-incidents").json()["items"]
        mine = [i for i in items if i["incident_id"] == incident_id][0]
        self.assertEqual(mine["status"], "new")
        self.assertIsNotNone(mine["subject"]["locked_until"])
        self.assertNotIn("contact", str(mine))
        r = admin.post(f"/api/admin/security-incidents/{incident_id}/actions", json={"action": "unlock", "note": "업무 착오 확인"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(c.get("/api/members").status_code, 200)
        detail = admin.get(f"/api/admin/security-incidents/{incident_id}").json()
        self.assertEqual(detail["status"], "reviewing")          # 첫 조치 → 검토 중
        self.assertEqual(detail["actions"][0]["action"], "unlock")
        self.assertEqual(detail["actions"][0]["actor"], "A-D01")
        r = admin.post(f"/api/admin/security-incidents/{incident_id}/status", json={"status": "resolved", "note": "교육 완료"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(incident_id, [i["incident_id"] for i in admin.get("/api/admin/security-incidents").json()["items"]])
        self.assertIn(incident_id, [i["incident_id"] for i in admin.get("/api/admin/security-incidents?status=all").json()["items"]])

    def test_suspend_and_restore_staff(self):
        c, incident_id = self.lock_counselor()
        admin = self.login(DATA_ADMIN)
        r = admin.post(f"/api/admin/security-incidents/{incident_id}/actions", json={"action": "suspend_account"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["subject_role"], "counselor")
        self.assertEqual(r.json()["keycloak"], "keycloak_not_configured")
        self.assertEqual(c.get("/api/members").status_code, 401)            # 세션 삭제 → 다시 로그인해야 함
        self.assertEqual(self.login(COUNSELOR_A).get("/api/members").status_code, 401)   # 새로 로그인해도 비활성
        r = admin.post(f"/api/admin/security-incidents/{incident_id}/actions", json={"action": "restore_account"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.login(COUNSELOR_A).get("/api/members").status_code, 200)   # 복구하면 잠금도 해제

    def test_cannot_suspend_self_or_admin(self):
        with self.db.connection() as conn:
            row = conn.execute("""INSERT INTO security_incidents (kind, severity, subject_user_id, subject_code, subject_role,
                                         source, detail, blocked) VALUES ('repeated_denials','medium',%s,'A-D01','data_admin',
                                         'internal-api','test',true) RETURNING incident_id""", (DATA_ADMIN,)).fetchone()
        admin = self.login(DATA_ADMIN)
        r = admin.post(f"/api/admin/security-incidents/{row['incident_id']}/actions", json={"action": "suspend_account"})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.login(DATA_ADMIN).get("/api/members").status_code, 200)

    def test_incident_api_is_admin_only(self):
        for uid in (COUNSELOR_B, APPROVER):
            c = self.login(uid)
            self.assertEqual(c.get("/api/admin/security-incidents").status_code, 403)
            self.assertEqual(c.post(f"/api/admin/security-incidents/{uuid.uuid4()}/actions",
                                    json={"action": "unlock"}).status_code, 403)

    def test_revoke_deliveries_only_for_member_subject(self):
        import httpx
        from app.routers import security as routes
        calls = []
        original = routes.transfer_client.call

        def call(request, method, path, **kw):
            calls.append((method, path))
            return httpx.Response(200, json={"revoked": 2})
        routes.transfer_client.call = call
        try:
            _, staff_incident = self.lock_counselor()
            admin = self.login(DATA_ADMIN)
            r = admin.post(f"/api/admin/security-incidents/{staff_incident}/actions", json={"action": "revoke_deliveries"})
            self.assertEqual(r.status_code, 409)
            with self.as_member(MEMBER_B) as m:
                incident_id = m.post("/api/internal/security-events",
                                     json={"kind": "approval_mismatch", "reason": "requested_file_not_approved",
                                           "blocked": True}).json()["incident_id"]
            r = admin.post(f"/api/admin/security-incidents/{incident_id}/actions", json={"action": "revoke_deliveries"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["revoked"], 2)
            self.assertEqual(calls, [("POST", f"/api/security/recipients/{MEMBER_B}/revoke-deliveries")])
        finally:
            routes.transfer_client.call = original

    # ---------- 공격 ② (중계가 알림) ----------
    def test_member_mismatch_reports_lock_and_status(self):
        body = {"kind": "approval_mismatch", "reason": "requested_file_not_approved", "blocked": True,
                "delivery_id": str(uuid.uuid4())}
        with self.as_member(MEMBER_B) as m:
            first = m.post("/api/internal/security-events", json=body)
            self.assertEqual(first.status_code, 200, first.text)
            self.assertIsNone(first.json()["locked_until"])
            self.assertEqual(m.get("/api/internal/my-status").json()["status"], "active")
            m.post("/api/internal/security-events", json=body)
            third = m.post("/api/internal/security-events", json=body).json()
            self.assertTrue(third["newly_locked"])
            status = m.get("/api/internal/my-status").json()
            self.assertEqual(status["status"], "locked")
            # 본문으로 다른 회원을 지목할 수 없다 (대상은 토큰으로만 정함)
            bad = m.post("/api/internal/security-events", json={**body, "subject_user_id": COUNSELOR_A})
            self.assertEqual(bad.status_code, 200)
        inc = self.incidents(MEMBER_B, "approval_mismatch")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["source"], "transfer-api")
        self.assertGreaterEqual(inc[0]["occurrences"], 3)
        self.assertEqual(self.incidents(COUNSELOR_A, "approval_mismatch"), [])
        # 총관리자 정지 → suspended
        admin = self.login(DATA_ADMIN)
        r = admin.post(f"/api/admin/security-incidents/{inc[0]['incident_id']}/actions", json={"action": "suspend_account"})
        self.assertEqual(r.status_code, 200, r.text)
        with self.as_member(MEMBER_B) as m:
            self.assertEqual(m.get("/api/internal/my-status").json()["status"], "suspended")

    # ---------- 다운로드 토큰 오용 (중계가 알림) ----------
    def test_token_misuse_reports_and_locks(self):
        body = {"kind": "download_token_misuse", "reason": "download_token_used", "blocked": True,
                "delivery_id": str(uuid.uuid4())}
        with self.as_member(MEMBER_B) as m:
            first = m.post("/api/internal/security-events", json={**body, "reason": "download_token_required"})
            self.assertEqual(first.status_code, 200, first.text)
            m.post("/api/internal/security-events", json=body)
            third = m.post("/api/internal/security-events", json=body).json()
            self.assertTrue(third["newly_locked"])
            self.assertEqual(m.get("/api/internal/my-status").json()["status"], "locked")
            bad = m.post("/api/internal/security-events", json={**body, "kind": "something_else"})
            self.assertEqual(bad.status_code, 422)
        inc = self.incidents(MEMBER_B, "download_token_misuse")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "medium")          # 첫 사건(토큰 생략)의 등급, 이후 횟수만 늘어남
        self.assertGreaterEqual(inc[0]["occurrences"], 3)
        self.assertIsNotNone(inc[0]["auto_locked_until"])
        with self.db.connection() as conn:
            reason = conn.execute("SELECT reason FROM account_locks WHERE user_id = %s", (MEMBER_B,)).fetchone()["reason"]
        self.assertEqual(reason, "repeated_download_token_misuse")

    def test_baseline_detected_but_not_blocked_is_recorded(self):
        if os.environ.get("ALLOW_EXPORT_TEST") != "1":
            self.skipTest("실제 내보내기 행을 만드는 시험 (ALLOW_EXPORT_TEST=1 일 때만)")
        os.environ["GATE_MODE"] = "baseline"
        try:
            c = self.login(COUNSELOR_A)
            self.assertEqual(c.post("/api/admin/member-exports").status_code, 201)
        finally:
            os.environ["GATE_MODE"] = "enforce"
        inc = self.incidents(COUNSELOR_A, "unauthorized_export")
        self.assertEqual(len(inc), 1)
        self.assertFalse(inc[0]["blocked"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
