"""internal-api 권한 동작 검사 (실제 business-db + 시드 데이터 기준).

경로 선언 검사(test_routes.py)와 달리, 실제 요청을 보내 서버가 막는지 확인한다.
- 다른 상담 직원 담당 회원: 조회·수정·탈퇴 모두 404 (존재 여부를 알리지 않음)
- 즉시 탈퇴는 총관리자만, 총관리자가 요청한 탈퇴는 상담 직원이 철회 불가
- 알림은 본인 것만 조회·읽음·삭제
- 역할 밖 기능(승인 담당 회원 조회, 상담 직원 전체 내보내기, 총관리자 소개 자료 요청) 403
- 회원 본인 기능: 서비스 토큰 없으면 401, 직원이 처리한 탈퇴는 회원이 철회 불가, 탈퇴 안내(my-status)

로그인(Keycloak)과 CSRF 는 의존성 바꿔치기로 건너뛰고, 권한 판단 코드는 그대로 실행한다.
데이터를 바꾸는 검사는 끝나면 원래대로 되돌린다 (탈퇴 → 철회, 시험 알림 삭제).

실행 (privacygate 폴더에서, 시드 데이터가 들어 있는 상태):
  docker compose exec -T internal-api python - < ../matchmaking-internal/tests/test_permissions.py
"""
import contextlib
import logging
import os
import sys
import unittest
import uuid

os.environ["AUDIT_LOG_PATH"] = "/tmp/test-permissions-audit.json"   # 시험 기록이 실제 감사 로그(Wazuh)에 섞이지 않게
sys.path.insert(0, os.getcwd())                                       # 컨테이너 /srv (app 패키지)

try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None

COUNSELOR_A = "11111111-1111-4111-8111-111111111101"
DATA_ADMIN = "11111111-1111-4111-8111-111111111102"
APPROVER = "11111111-1111-4111-8111-111111111103"
COUNSELOR_B = "11111111-1111-4111-8111-111111111104"
MEMBER_B = "22222222-2222-4222-8222-222222222201"      # A-003 박도윤 (counselor_a 담당)


def member(n: int) -> str:
    """시드 회원 A-0NN 의 member_id."""
    return f"bbbbbbbb-0000-4000-8000-{n:012d}"


STAFF = {COUNSELOR_A: ("A-C01", "counselor"), COUNSELOR_B: ("A-C02", "counselor"),
         DATA_ADMIN: ("A-D01", "data_admin"), APPROVER: ("A-P01", "approver")}


@unittest.skipIf(TestClient is None, "internal-api 컨테이너 안에서 실행")
class Permissions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import audit, db
        audit._insert = lambda event: None      # 시험 요청은 audit_log 테이블에도 남기지 않음 (app.main 보다 먼저)
        from app.auth import session
        from app.config import get_settings
        from app.main import app
        from privacygate.policy import Principal

        logging.getLogger("httpx").setLevel(logging.WARNING)
        db.open_pool(get_settings().database_url)
        cls.db, cls.app, cls.session, cls.Principal = db, app, session, Principal
        cls.client = TestClient(app, raise_server_exceptions=False)   # lifespan(주기 작업)은 켜지 않음
        with db.connection() as conn:
            seeded = conn.execute("SELECT count(*) AS n FROM members WHERE member_id = ANY(%s)",
                                  ([member(1), member(3), member(11)],)).fetchone()["n"]
        if seeded != 3:
            raise unittest.SkipTest("시드 회원(A-001, A-003, A-011)이 없습니다. 시드 데이터 상태에서 실행하세요")
        app.dependency_overrides[session.require_csrf] = lambda: None
        cls.started = cls._db_now()

    @classmethod
    def tearDownClass(cls):
        cls.app.dependency_overrides.clear()
        with cls.db.connection() as conn:     # 시험 중 생긴 알림 정리
            conn.execute("DELETE FROM notifications WHERE created_at >= %s", (cls.started,))
        cls.db.close_pool()

    @classmethod
    def _db_now(cls):
        with cls.db.connection() as conn:
            return conn.execute("SELECT now() AS t").fetchone()["t"]

    # ---------- 도우미 ----------
    @contextlib.contextmanager
    def as_staff(self, user_id):
        pseudo, role = STAFF[user_id]
        p = self.Principal(user_id=user_id, pseudo_id=pseudo, role=role)
        self.app.dependency_overrides[self.session.current_principal] = lambda: p
        try:
            yield self.client
        finally:
            self.app.dependency_overrides.pop(self.session.current_principal, None)

    @contextlib.contextmanager
    def as_member(self, user_id):
        p = self.Principal(user_id=user_id, pseudo_id="A-003", role="member")
        o = self.app.dependency_overrides
        o[self.session.member_via_transfer] = lambda: p
        o[self.session.member_token_via_transfer] = lambda: user_id
        try:
            yield self.client
        finally:
            o.pop(self.session.member_via_transfer, None)
            o.pop(self.session.member_token_via_transfer, None)

    def status_of(self, member_id):
        with self.db.connection() as conn:
            return conn.execute("SELECT status FROM members WHERE member_id = %s", (member_id,)).fetchone()["status"]

    def code(self, resp):
        return resp.json().get("error", {}).get("code")

    # ---------- 담당 범위 ----------
    def test_counselor_sees_only_assigned_members(self):
        with self.as_staff(COUNSELOR_A) as c:
            r = c.get("/api/members")
            self.assertEqual(r.status_code, 200)
            ids = {m["member_id"] for m in r.json()["items"]}
            self.assertIn(member(1), ids)
            self.assertNotIn(member(11), ids)            # counselor_b 담당
        with self.as_staff(DATA_ADMIN) as c:
            ids = {m["member_id"] for m in c.get("/api/members").json()["items"]}
            self.assertTrue({member(1), member(11)} <= ids)   # 총관리자는 전체

    def test_other_counselors_member_is_404(self):
        other = member(11)
        with self.as_staff(COUNSELOR_A) as c:
            self.assertEqual(c.get(f"/api/members/{other}").status_code, 404)
            self.assertEqual(c.patch(f"/api/members/{other}", json={"introduction": "x"}).status_code, 404)
            self.assertEqual(c.post(f"/api/members/{other}/withdraw", json={"mode": "scheduled"}).status_code, 404)
            self.assertEqual(c.post(f"/api/members/{other}/withdraw/cancel").status_code, 404)
            # 없는 회원과 같은 응답 (존재 여부를 알리지 않음)
            self.assertEqual(c.get(f"/api/members/{uuid.uuid4()}").status_code, 404)
            self.assertEqual(c.get(f"/api/members/{member(1)}").status_code, 200)
        self.assertEqual(self.status_of(other), "active")

    def test_other_counselors_evidence_list_is_hidden(self):
        with self.as_staff(COUNSELOR_A) as c:
            r = c.get("/api/evidence-files")
            self.assertEqual(r.status_code, 200)
            seen = {e["member_id"] for e in r.json()["items"]}
        with self.db.connection() as conn:
            mine = {str(x["member_id"]) for x in conn.execute(
                "SELECT member_id FROM assignments WHERE user_id = %s", (COUNSELOR_A,)).fetchall()}
        self.assertTrue(seen <= mine, seen - mine)      # 담당 회원 증빙만 보임

    # ---------- 역할 ----------
    def test_role_limits(self):
        with self.as_staff(APPROVER) as c:
            self.assertEqual(c.get("/api/members").status_code, 403)
            self.assertEqual(c.get(f"/api/members/{member(1)}").status_code, 403)
        with self.as_staff(COUNSELOR_A) as c:
            self.assertEqual(c.post("/api/admin/member-exports", json={}).status_code, 403)
            self.assertEqual(c.get("/api/admin/member-exports").status_code, 403)
        with self.as_staff(DATA_ADMIN) as c:   # 소개 자료 발송 요청은 담당 상담 직원만
            r = c.post(f"/api/members/{member(1)}/introductions", json={"consent_id": str(uuid.uuid4())})
            self.assertEqual(r.status_code, 403)

    # ---------- 탈퇴 권한 ----------
    def test_immediate_withdraw_is_admin_only(self):
        with self.as_staff(COUNSELOR_A) as c:
            r = c.post(f"/api/members/{member(1)}/withdraw", json={"mode": "immediate"})
            self.assertEqual(r.status_code, 403)
            self.assertEqual(self.code(r), "ACCESS_DENIED")
        self.assertEqual(self.status_of(member(1)), "active")

    def test_counselor_cannot_cancel_admin_requested_withdraw(self):
        target = member(2)
        with self.as_staff(DATA_ADMIN) as c:
            r = c.post(f"/api/members/{target}/withdraw", json={"mode": "scheduled", "reason": "권한 시험"})
            self.assertEqual(r.status_code, 200, r.text)
        try:
            with self.as_staff(COUNSELOR_A) as c:
                r = c.post(f"/api/members/{target}/withdraw/cancel")
                self.assertEqual(r.status_code, 403)
                self.assertEqual(self.status_of(target), "withdraw_pending")
        finally:
            with self.as_staff(DATA_ADMIN) as c:
                self.assertEqual(c.post(f"/api/members/{target}/withdraw/cancel").status_code, 200)
        self.assertEqual(self.status_of(target), "active")

    def test_counselor_can_cancel_own_withdraw(self):
        target = member(4)
        with self.as_staff(COUNSELOR_A) as c:
            self.assertEqual(c.post(f"/api/members/{target}/withdraw", json={"mode": "scheduled"}).status_code, 200)
            self.assertEqual(c.post(f"/api/members/{target}/withdraw/cancel").status_code, 200)
        self.assertEqual(self.status_of(target), "active")

    # ---------- 알림 ----------
    def test_notifications_are_own_only(self):
        with self.db.connection() as conn:
            nid = conn.execute("""INSERT INTO notifications (user_id, kind, title) VALUES (%s, 'test', '권한 시험')
                                  RETURNING notification_id""", (COUNSELOR_B,)).fetchone()["notification_id"]
        try:
            with self.as_staff(COUNSELOR_A) as c:
                items = c.get("/api/notifications").json()["items"]
                self.assertNotIn(str(nid), {n["notification_id"] for n in items})
                self.assertEqual(c.post("/api/notifications/read", json={"ids": [str(nid)]}).json()["updated"], 0)
                self.assertEqual(c.post("/api/notifications/delete", json={"ids": [str(nid)]}).json()["deleted"], 0)
            with self.db.connection() as conn:
                row = conn.execute("SELECT read_at FROM notifications WHERE notification_id = %s", (nid,)).fetchone()
            self.assertIsNotNone(row)            # 남의 알림은 지워지지 않음
            self.assertIsNone(row["read_at"])    # 읽음 처리도 안 됨
            with self.as_staff(COUNSELOR_B) as c:
                self.assertIn(str(nid), {n["notification_id"] for n in c.get("/api/notifications").json()["items"]})
        finally:
            with self.db.connection() as conn:
                conn.execute("DELETE FROM notifications WHERE notification_id = %s", (nid,))

    # ---------- 회원 본인 기능 ----------
    def test_member_routes_need_service_token(self):
        for path in ("/api/internal/my-status", "/api/internal/my-matches", "/api/internal/my-consents"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        self.assertEqual(self.client.post("/api/internal/my-withdrawal", json={}).status_code, 401)

    def test_member_status_and_self_withdraw(self):
        target = member(3)
        with self.as_member(MEMBER_B) as c:
            self.assertEqual(c.get("/api/internal/my-status").json()["status"], "active")
            r = c.post("/api/internal/my-withdrawal", json={"reason": "시험"})
            self.assertEqual(r.status_code, 200, r.text)
            try:
                s = c.get("/api/internal/my-status").json()
                self.assertEqual((s["status"], s["by"], s["can_cancel"]), ("withdraw_pending", "self", True))
                self.assertIsNone(s["reason"])               # 본인 신청이면 사유를 다시 보여 주지 않음
                self.assertEqual(c.get("/api/internal/my-matches").status_code, 403)   # 유예 중 회원 기능 막힘
            finally:
                self.assertEqual(c.post("/api/internal/my-withdrawal/cancel").status_code, 200)
        self.assertEqual(self.status_of(target), "active")

    def test_member_cannot_cancel_staff_withdraw(self):
        target = member(3)
        with self.as_staff(COUNSELOR_A) as c:
            self.assertEqual(c.post(f"/api/members/{target}/withdraw",
                                    json={"mode": "scheduled", "reason": "권한 시험 사유"}).status_code, 200)
        try:
            with self.as_member(MEMBER_B) as c:
                s = c.get("/api/internal/my-status").json()
                self.assertEqual((s["status"], s["by"], s["can_cancel"]), ("withdraw_pending", "staff", False))
                self.assertEqual(s["reason"], "권한 시험 사유")
                self.assertIn("관리자에 의해", s["message"])
                self.assertEqual(c.post("/api/internal/my-withdrawal/cancel").status_code, 403)
        finally:
            with self.as_staff(COUNSELOR_A) as c:
                self.assertEqual(c.post(f"/api/members/{target}/withdraw/cancel").status_code, 200)
        self.assertEqual(self.status_of(target), "active")

    def test_unknown_member_status(self):
        with self.as_member(str(uuid.uuid4())) as c:
            self.assertEqual(c.get("/api/internal/my-status").json()["status"], "not_registered")


class _FakeResp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


class _FakeKeycloak:
    """Keycloak 관리 API 흉내: 역할 조회와 삭제 호출만 기록한다."""
    def __init__(self, roles):
        self.roles, self.deleted = roles, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url):
        return _FakeResp(404) if self.roles is None else _FakeResp(200, [{"name": r} for r in self.roles])

    def delete(self, url):
        self.deleted.append(url)
        return _FakeResp(204)


@unittest.skipIf(TestClient is None, "internal-api 컨테이너 안에서 실행")
class KeycloakCleanup(unittest.TestCase):
    """탈퇴 회원 Keycloak 계정 삭제는 member 역할 계정만 (직원 계정은 거부)."""
    def run_delete(self, roles):
        from app import keycloak_admin as ka
        fake = _FakeKeycloak(roles)
        orig = ka._client, ka._base
        ka._client, ka._base = (lambda: fake), (lambda: "http://kc/admin/realms/matchmaking")
        self.addCleanup(setattr, ka, "_client", orig[0])
        self.addCleanup(setattr, ka, "_base", orig[1])
        return ka, fake, (lambda: ka.delete_member(MEMBER_B))

    def test_member_account_deleted(self):
        _, fake, call = self.run_delete(["member", "default-roles-matchmaking"])
        self.assertEqual(call(), "deleted")
        self.assertEqual(len(fake.deleted), 1)

    def test_staff_account_refused(self):
        for roles in (["counselor"], ["member", "data_admin"], ["approver"]):
            ka, fake, call = self.run_delete(roles)
            with self.assertRaises(ka.KeycloakAdminError):
                call()
            self.assertEqual(fake.deleted, [])

    def test_missing_account(self):
        _, fake, call = self.run_delete(None)
        self.assertEqual(call(), "not_found")


if __name__ == "__main__":
    unittest.main(argv=["test_permissions"], verbosity=2)
