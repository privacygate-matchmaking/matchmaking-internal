"""회원가입 내부 계약: 서비스 토큰·입력 검사·Keycloak 계정 생성·DB 실패 시 되돌리기. 비밀번호는 남기지 않는다."""
from contextlib import contextmanager
from datetime import date
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from privacygate.audit import AuditWriter
from privacygate.errors import ErrorCode, GateError
from privacygate.web import assert_all_routes_guarded, install

from app import audit, db, keycloak_admin
from app.auth import oidc, session
from app.routers import signup

PASSWORD = 'Synthetic-Pass-2026!'
UID = '33333333-3333-4333-8333-000000000001'


def body(**extra):
    data = {'username': 'newmember1', 'password': PASSWORD, 'name': ' 가상 회원 ', 'gender': '여', 'birth_date': '1995-04-01',
            'contact_phone': '01012345678', 'contact_email': 'newmember1@example.test',
            'privacy_consent': True, 'consent_version': '2026-11', 'education_level': '4년제 대졸', 'job_group': ' IT ',
            'height_cm': 170, 'weight_kg': 60, 'introduction': ' 합성 소개 '}
    data.update(extra)
    return data


@pytest.fixture
def client(tmp_path, monkeypatch):
    calls = {'created': [], 'removed': [], 'saved': [], 'audit': []}

    class Verifier:
        def verify(self, token):
            entries = {'service': 'transfer-api', 'external': 'external-api'}
            if token not in entries:
                raise GateError(ErrorCode.AUTH_REQUIRED, 'invalid_token')
            return {'sub': 'svc', 'azp': entries[token], 'realm_access': {'roles': []}}
    monkeypatch.setattr(oidc, 'discovery', lambda: {'issuer': 'test', 'jwks_uri': 'test'})
    monkeypatch.setattr(oidc, 'get_settings', lambda: SimpleNamespace(api_audience='internal-api'))
    monkeypatch.setattr(oidc, '_cache', {'svc': Verifier()})
    monkeypatch.setattr(session, 'service_verifier', lambda: Verifier())

    @contextmanager
    def connection():
        yield 'conn'
    monkeypatch.setattr(db, 'connection', connection)
    monkeypatch.setattr(audit, 'allow', lambda r, **k: calls['audit'].append(('allow', k)))
    monkeypatch.setattr(audit, 'deny', lambda r, reason, **k: calls['audit'].append(('deny', reason)))
    monkeypatch.setattr(keycloak_admin, 'enabled', lambda: True)

    def create(username, password, email):
        if calls.get('kc_error'):
            raise keycloak_admin.KeycloakAdminError(calls['kc_error'])
        calls['created'].append((username, password, email))
        return UID
    monkeypatch.setattr(keycloak_admin, 'create_member', create)
    monkeypatch.setattr(keycloak_admin, 'remove_new_member', lambda uid: calls['removed'].append(uid))

    def save(conn, user_id, values, version):
        if calls.get('db_error'):
            raise RuntimeError('db down')
        calls['saved'].append((user_id, values, version))
        return {'member_id': 'm', 'pseudo_id': 'A-021', 'counselor_id': 'c'}
    monkeypatch.setattr(signup, 'save', save)
    app = FastAPI()
    install(app, AuditWriter('test-internal', str(tmp_path / 'audit.json')))
    app.include_router(signup.router)
    assert_all_routes_guarded(app)
    with TestClient(app) as tc:
        yield tc, calls


SVC = {'Authorization': 'Bearer service'}


def test_signup_creates_account_then_member(client):
    tc, calls = client
    r = tc.post('/api/internal/member-signups', json=body(), headers=SVC)
    assert r.status_code == 201, r.text
    assert r.json() == {'status': 'registered', 'username': 'newmember1'}
    assert calls['created'] == [('newmember1', PASSWORD, 'newmember1@example.test')]
    uid, values, version = calls['saved'][0]
    assert uid == UID and version == '2026-11' and 'password' not in values
    assert values['name'] == '가상 회원' and values['contact_phone'] == '010-1234-5678'
    assert values['job_group'] == 'IT' and values['introduction'] == '합성 소개' and values['height_cm'] == 170
    assert ('allow', {'action': 'member.signup', 'target_type': 'member', 'target_id': 'A-021', 'reason': 'assigned'}) in calls['audit']
    assert PASSWORD not in repr(calls['audit']) and 'A-021' not in r.text


def test_signup_only_from_transfer_service(client):
    tc, calls = client
    assert tc.post('/api/internal/member-signups', json=body()).status_code == 401
    assert tc.post('/api/internal/member-signups', json=body(), headers={'Authorization': 'Bearer external'}).status_code == 403
    assert not calls['created']


@pytest.mark.parametrize('bad,reason', [
    ({'birth_date': f'{date.today().year - 18}-01-01'}, 'underage'),
    ({'contact_phone': '02-123-4567'}, 'phone_invalid'),
    ({'contact_email': 'not-an-email'}, 'email_invalid'),
    ({'username': '1abc'}, 'username_invalid'),
    ({'introduction': '   '}, 'introduction_required'),
    ({'password': 'xxnewmember1xx'}, 'password_contains_username'),
])
def test_signup_rejects_invalid_values_before_account(client, bad, reason):
    tc, calls = client
    r = tc.post('/api/internal/member-signups', json=body(**bad), headers=SVC)
    assert r.status_code == 422 and r.json()['error'].get('message'), r.text
    assert not calls['created'] and PASSWORD not in r.text


@pytest.mark.parametrize('bad', [{'privacy_consent': False}, {'gender': '기타'}, {'role': 'counselor'}, {'height_cm': 300},
                                 {'education_level': None}, {'job_group': ''}, {'weight_kg': None}, {'introduction': ''}])
def test_signup_schema(client, bad):
    tc, calls = client
    assert tc.post('/api/internal/member-signups', json=body(**bad), headers=SVC).status_code == 422
    assert not calls['created']


def test_signup_duplicate_account(client):
    tc, calls = client
    calls['kc_error'] = 'account_exists'
    r = tc.post('/api/internal/member-signups', json=body(), headers=SVC)
    assert r.status_code == 409 and '이미 사용 중' in r.json()['error']['message']
    assert ('deny', 'signup:account_exists') in calls['audit'] and not calls['saved']


def test_signup_db_failure_removes_new_account(client):
    tc, calls = client
    calls['db_error'] = True
    r = tc.post('/api/internal/member-signups', json=body(), headers=SVC)
    assert r.status_code == 500 and calls['removed'] == [UID]
    assert ('deny', 'signup:db_failed') in calls['audit']


class FakeKC:
    def __init__(self, status=201, roles=('member', 'default-roles-matchmaking'), body=None):
        self.status, self.roles, self.body, self.deleted, self.posted = status, roles, body or {}, [], None
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def post(self, url, json):
        self.posted = json
        return SimpleNamespace(status_code=self.status, json=lambda: self.body,
                               headers={'Location': f'http://kc/admin/realms/matchmaking/users/{UID}'})
    def get(self, url):
        return SimpleNamespace(status_code=200, json=lambda: [{'name': r} for r in self.roles])
    def delete(self, url):
        self.deleted.append(url)


@pytest.mark.parametrize('kc,expect', [
    (FakeKC(), UID),
    (FakeKC(status=409), 'account_exists'),
    (FakeKC(status=400, body={'errorMessage': 'invalidPasswordMinLengthMessage'}), 'password_policy'),
    (FakeKC(status=400, body={'errorMessage': 'error-invalid-email'}), 'account_invalid'),
    (FakeKC(roles=('default-roles-matchmaking',)), 'member_role_missing'),
    (FakeKC(roles=('member', 'counselor')), 'member_role_missing'),
])
def test_keycloak_create_member(monkeypatch, kc, expect):
    monkeypatch.setattr(keycloak_admin, '_client', lambda: kc)
    monkeypatch.setattr(keycloak_admin, '_base', lambda: 'http://kc/admin/realms/matchmaking')
    try:
        result = keycloak_admin.create_member('newmember1', PASSWORD, 'n@example.test')
    except keycloak_admin.KeycloakAdminError as exc:
        result = str(exc)
    assert result == expect
    assert kc.posted['groups'] == ['/members'] and 'realmRoles' not in kc.posted
    assert kc.posted['credentials'][0]['temporary'] is False
    if expect == 'member_role_missing':
        assert kc.deleted == [f'http://kc/admin/realms/matchmaking/users/{UID}']
