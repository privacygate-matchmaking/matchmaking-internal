"""회원 알림: 중계 서비스 토큰만 사건을 보낼 수 있고, 문구는 내부가 정하며, 조회·읽음·삭제는 본인 것만."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from privacygate.audit import AuditWriter
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import Principal
from privacygate.web import assert_all_routes_guarded, install

from app import audit, db
from app.auth import oidc, session
from app.routers import member_notify

B = '22222222-2222-4222-8222-222222222201'
C = '22222222-2222-4222-8222-222222222202'


class Conn:
    def __init__(self, log):
        self.log = log

    def execute(self, sql, params=()):
        self.log.append((' '.join(sql.split()), params))
        return SimpleNamespace(rowcount=1, fetchone=lambda: {'n': 3, 'user_id': B}, fetchall=lambda: [])


@pytest.fixture
def client(tmp_path, monkeypatch):
    log = []

    @contextmanager
    def connection():
        yield Conn(log)
    monkeypatch.setattr(db, 'connection', connection)
    monkeypatch.setattr(audit, 'allow', lambda *a, **k: None)

    class Verifier:
        def verify(self, token):
            if token not in ('service', 'external'):
                raise GateError(ErrorCode.AUTH_REQUIRED, 'invalid_token')
            return {'sub': 'svc', 'azp': 'transfer-api' if token == 'service' else 'external-api'}
    monkeypatch.setattr(oidc, 'discovery', lambda: {'issuer': 'test', 'jwks_uri': 'test'})
    monkeypatch.setattr(oidc, 'get_settings', lambda: SimpleNamespace(api_audience='internal-api'))
    monkeypatch.setattr(oidc, '_cache', {'svc': Verifier()})
    monkeypatch.setattr(session, 'service_verifier', lambda: Verifier())
    app = FastAPI()
    install(app, AuditWriter('t', str(tmp_path / 'a.json')))
    app.include_router(member_notify.router)
    assert_all_routes_guarded(app)
    app.dependency_overrides[session.member_via_transfer] = lambda: Principal(user_id=B, pseudo_id='A-003', role='member')
    with TestClient(app) as tc:
        yield tc, log


SVC = {'Authorization': 'Bearer service'}


def test_event_uses_internal_text_and_member_only_insert(client):
    tc, log = client
    r = tc.post('/api/internal/member-notification-events', json={'user_ids': [B, C], 'kind': 'match_requested'}, headers=SVC)
    assert r.status_code == 200 and r.json() == {'created': 2}
    inserts = [(s, p) for s, p in log if 'INSERT INTO notifications' in s]
    assert len(inserts) == 2 and all("u.role = 'member' AND u.active" in s for s, _ in inserts)
    assert inserts[0][1][:2] == ('member_match_requested', '새 매칭 신청') and inserts[0][1][3] == 'matches'


@pytest.mark.parametrize('bad', [{'user_ids': [B], 'kind': 'free_text'}, {'user_ids': [B], 'kind': 'match_requested', 'title': 'x'},
                                 {'user_ids': [], 'kind': 'match_requested'}, {'user_ids': [B, C, B], 'kind': 'match_requested'}])
def test_event_rejects_unknown_kind_text_or_too_many(client, bad):
    tc, log = client
    assert tc.post('/api/internal/member-notification-events', json=bad, headers=SVC).status_code == 422
    assert not log


def test_event_requires_transfer_service(client):
    tc, log = client
    body = {'user_ids': [B], 'kind': 'match_requested'}
    assert tc.post('/api/internal/member-notification-events', json=body).status_code == 401
    assert tc.post('/api/internal/member-notification-events', json=body, headers={'Authorization': 'Bearer external'}).status_code == 403
    assert not log


def test_my_notifications_are_scoped_to_member(client):
    tc, log = client
    assert tc.get('/api/internal/my-notifications').json() == {'unread': 3, 'items': []}
    assert tc.post('/api/internal/my-notifications/read', json={'all': True}).json() == {'updated': 1, 'unread': 3}
    assert tc.post('/api/internal/my-notifications/delete', json={'ids': [C]}).status_code == 200
    assert all(p[0] == B for s, p in log if 'notifications' in s)
    assert tc.post('/api/internal/my-notifications/read', json={'user_id': C}).status_code == 422


def test_evidence_review_notification_text():
    log = []
    member_notify.evidence_reviewed(Conn(log), 'm1', 'photo', 'rejected')
    ins = [p for s, p in log if 'INSERT INTO notifications' in s][0]
    assert ins[0] == 'member_evidence_rejected' and '프로필 사진' in ins[2] and ins[3] == 'account'
