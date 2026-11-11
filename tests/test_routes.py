"""internal-api 경로 권한 선언 검사 (fastapi·privacygate 설치 환경에서 실행)."""
import os
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "internal-api"))
sys.path.insert(0, str(ROOT.parent / "privacygate" / "src"))

try:
    import fastapi  # noqa: F401
    import jwt  # noqa: F401
    import psycopg  # noqa: F401
    import httpx  # noqa: F401
except ImportError:
    fastapi = None

# docs/permissions.md 와 같아야 한다
EXPECTED = {
    ("GET", "/api/me"): "roles:approver,counselor,data_admin",
    ("GET", "/api/members"): "roles:counselor,data_admin",          # 상담: 담당만, 총관리자: 전체
    ("GET", "/api/members/{member_id}"): "roles:counselor,data_admin",
    ("PATCH", "/api/members/{member_id}"): "roles:counselor,data_admin",          # 명세 외 추가
    ("POST", "/api/members/{member_id}/withdraw"): "roles:counselor,data_admin",  # 명세 외 추가
    ("POST", "/api/admin/member-exports"): "roles:data_admin",
    ("GET", "/api/admin/member-exports"): "roles:data_admin",   # 내보내기 내역 (명세 외 추가)
    ("POST", "/api/evidence-files"): "service:transfer-api",   # 회원 제출, 중계 경유
    ("GET", "/api/evidence-files"): "roles:counselor,data_admin",   # 담당 회원 증빙 (명세 외 추가)
    ("GET", "/api/internal/my-evidence-files"): "service:transfer-api",            # 명세 외 추가
    ("POST", "/api/member-exports/{export_id}/transfer-files"): "roles:counselor",  # 명세 외 추가
    ("GET", "/api/internal/my-consents"): "service:transfer-api",                  # 명세 외 추가
    ("POST", "/api/internal/my-consents"): "service:transfer-api",                 # 명세 외 추가
    ("POST", "/api/internal/my-consents/{consent_id}/revoke"): "service:transfer-api",  # 명세 외 추가
    ("GET", "/api/evidence-files/{file_id}/content"): "roles:counselor,data_admin",
    ("POST", "/api/evidence-files/{file_id}/review"): "roles:counselor,data_admin",
    ("GET", "/api/internal/my-matches"): "service:transfer-api",                       # 명세 외 추가
    ("POST", "/api/internal/my-matches"): "service:transfer-api",                      # 명세 외 추가
    ("POST", "/api/internal/my-matches/{counterpart_member_id}/cancel"): "service:transfer-api",  # 명세 외 추가
    ("POST", "/api/internal/disclosure-checks"): "service:transfer-api",
    ("POST", "/api/transfer-files"): "roles:counselor",
    ("POST", "/api/export-requests"): "roles:counselor",
    ("GET", "/api/export-requests"): "roles:approver,counselor",
    ("GET", "/api/export-requests/{request_id}"): "roles:approver,counselor",
    ("POST", "/api/export-requests/{request_id}/approve"): "roles:approver",
    ("POST", "/api/export-requests/{request_id}/reject"): "roles:approver",
    ("POST", "/api/approvals/{approval_id}/revoke"): "roles:approver",
}


@unittest.skipIf(fastapi is None, "fastapi 등 의존성 필요 (docker 컨테이너 안에서 실행)")
class RouteGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for k in ("DATABASE_URL", "OIDC_DISCOVERY_URL", "OIDC_CLIENT_SECRET", "APP_BASE_URL"):
            os.environ.setdefault(k, "http://test")
        from app.main import app  # 권한 선언 누락 시 여기서 실패
        from privacygate.web import route_policies
        cls.policies = route_policies(app)

    def test_expected_roles(self):
        for key, policy in EXPECTED.items():
            self.assertIn(policy, self.policies.get(key, []), key)

    def test_role_policy_is_single(self):
        for key, found in self.policies.items():
            if key[1].startswith("/api"):
                self.assertEqual(len([p for p in found if p.startswith("roles:")]) <= 1, True, key)


if __name__ == "__main__":
    unittest.main()
