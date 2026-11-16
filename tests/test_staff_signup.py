"""직원 가입 신청·총관리자 승인: Origin·횟수 제한, 역할 제한, Keycloak 비활성 생성·승인 활성화, 실패 시 되돌리기."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from privacygate.audit import AuditWriter
from privacygate.policy import Principal
from privacygate.web import assert_all_routes_guarded, install

from app import audit, db, keycloak_admin
from app.auth import session
from app.routers import staff_signup

PASSWORD = 'Synthetic-Staff-2026!'
KC_UID = '44444444-4444-4444-8444-000000000001'
SID = '55555555-5555-4555-8555-000000000001'
ADMIN = Principal(user_id='11111111-1111-4111-8111-111111111102', pseudo_id='A-D01', role='data_admin')
ORIGIN = {'Origin': 'https://internal.test'}


def body(**extra):
    data = {'username': 'newstaff1', 'password': PASSWORD, 'name': ' 가상 직원 ', 'email': 'newstaff1@example.test',
            'requested_role': 'counselor'}
    data.update(extra)
    return data


class Conn:
    def __init__(self, calls):
        self.calls = calls

    def execute(self, sql, params=()):
        self.calls['sql'].append((' '.join(sql.split()), params))
        if self.calls.get('db_error') and ('INSERT INTO staff_signups' in sql or 'approve_staff_signup(' in sql):
            raise RuntimeError('db down')
        row = None
        if 'INSERT INTO staff_signups' in sql:
            row = {'signup_id': SID}
        elif 'FROM staff_signups WHERE signup_id' in sql:
            row = self.calls.get('signup')
        elif 'approve_staff_signup(' in sql:
            row = {'user_id': KC_UID, 'pseudo_id': 'A-C03', 'role': 'counselor', 'username': 'newstaff1'}
        elif 'FROM staff_signups ORDER BY' in sql:
            return SimpleNamespace(fetchall=lambda: [dict(self.calls['signup'], created_at=None)] if self.calls.get('signup') else [])
        elif 'SELECT user_id FROM users WHERE role' in sql:
            return SimpleNamespace(fetchall=lambda: [{'user_id': 'other-' + params[0]}])
        return SimpleNamespace(fetchone=lambda: row, fetchall=lambda: [])


@pytest.fixture
def client(tmp_path, monkeypatch):
    calls = {'sql': [], 'kc': [], 'audit': []}

    @contextmanager
    def connection():
        yield Conn(calls)
    monkeypatch.setattr(db, 'connection', connection)
    monkeypatch.setattr(audit, 'allow', lambda r, **k: calls['audit'].append(('allow', k)))
    monkeypatch.setattr(audit, 'deny', lambda r, reason, **k: calls['audit'].append(('deny', reason)))
    monkeypatch.setattr(staff_signup, 'get_settings', lambda: SimpleNamespace(app_base_url='https://internal.test'))
    monkeypatch.setattr(staff_signup, 'limiter', staff_signup.Limiter())
    monkeypatch.setattr(keycloak_admin, 'enabled', lambda: True)

    def kc(name):
        def call(*args):
            if calls.get('kc_error') == name:
                raise keycloak_admin.KeycloakAdminError('account_exists' if name == 'create' else 'not_pending_account')
            calls['kc'].append((name,) + args)
            return KC_UID if name == 'create' else 'deleted'
        return call
    monkeypatch.setattr(keycloak_admin, 'create_staff_pending', kc('create'))
    monkeypatch.setattr(keycloak_admin, 'approve_staff', kc('approve'))
    monkeypatch.setattr(keycloak_admin, 'revert_staff', kc('revert'))
    monkeypatch.setattr(keycloak_admin, 'delete_pending_staff', kc('delete'))
    app = FastAPI()
    install(app, AuditWriter('test-internal', str(tmp_path / 'audit.json')))
    app.include_router(staff_signup.router)
    assert_all_routes_guarded(app)
    who = {'principal': ADMIN}

    def principal(request=None):
        if who['principal'] is None:
            from privacygate.errors import ErrorCode, GateError
            raise GateError(ErrorCode.AUTH_REQUIRED, 'no_session')
        return who['principal']
    app.dependency_overrides[session.current_principal] = principal
    app.dependency_overrides[session.require_csrf] = lambda: None
    with TestClient(app) as tc:
        yield tc, calls, who


def test_signup_creates_disabled_account_and_notifies_admin(client):
    tc, calls, _ = client
    r = tc.post('/api/staff-signups', json=body(), headers=ORIGIN)
    assert r.status_code == 201 and r.json() == {'status': 'pending'}, r.text
    assert calls['kc'] == [('create', 'newstaff1', PASSWORD, 'newstaff1@example.test', '가상 직원')]
    sql = ' | '.join(s for s, _ in calls['sql'])
    assert 'INSERT INTO staff_signups' in sql and 'INSERT INTO notifications' in sql
    assert PASSWORD not in repr(calls['sql']) + repr(calls['audit'])
    assert ('allow', {'action': 'staff_signup.request', 'target_type': 'staff_signup', 'target_id': SID, 'reason': 'counselor'}) in calls['audit']


@pytest.mark.parametrize('bad', [{'requested_role': 'data_admin'}, {'requested_role': 'member'}, {'role': 'approver'},
                                 {'password': 'short'}, {'username': 'A1'}])
def test_signup_schema_rejects_other_roles_and_shapes(client, bad):
    tc, calls, _ = client
    assert tc.post('/api/staff-signups', json=body(**bad), headers=ORIGIN).status_code == 422
    assert not calls['kc']


@pytest.mark.parametrize('bad,reason', [({'username': '1abc'}, 'username'), ({'email': 'nope'}, 'email'),
                                        ({'password': 'xxnewstaff1xxx'}, 'password')])
def test_signup_value_checks(client, bad, reason):
    tc, calls, _ = client
    r = tc.post('/api/staff-signups', json=body(**bad), headers=ORIGIN)
    assert r.status_code == 422 and r.json()['error'].get('message') and not calls['kc']


def test_signup_requires_origin_and_is_rate_limited(client):
    tc, calls, _ = client
    assert tc.post('/api/staff-signups', json=body()).status_code == 403
    assert tc.post('/api/staff-signups', json=body(), headers={'Origin': 'https://evil.test'}).status_code == 403
    assert not calls['kc']
    for _ in range(5):
        tc.post('/api/staff-signups', json=body(), headers={**ORIGIN, 'X-Forwarded-For': '10.0.0.1'})
    r = tc.post('/api/staff-signups', json=body(), headers={**ORIGIN, 'X-Forwarded-For': '10.0.0.1'})
    assert r.status_code == 409 and '잠시 후' in r.json()['error']['message']


def test_signup_duplicate_and_db_failure(client):
    tc, calls, _ = client
    calls['kc_error'] = 'create'
    r = tc.post('/api/staff-signups', json=body(), headers=ORIGIN)
    assert r.status_code == 409 and '이미 사용 중' in r.json()['error']['message']
    calls['kc_error'] = None
    calls['db_error'] = True
    r = tc.post('/api/staff-signups', json=body(), headers={**ORIGIN, 'X-Forwarded-For': '10.9.9.9'})
    assert r.status_code == 500 and ('delete', KC_UID) in calls['kc']


def signup(role='counselor'):
    return {'signup_id': SID, 'user_id': KC_UID, 'username': 'newstaff1', 'name': '가상 직원',
            'email': 'newstaff1@example.test', 'requested_role': role}


def test_admin_lists_and_approves(client):
    tc, calls, _ = client
    calls['signup'] = signup()
    items = tc.get('/api/staff-signups').json()['items']
    assert items[0]['username'] == 'newstaff1' and 'user_id' not in items[0]
    r = tc.post(f'/api/staff-signups/{SID}/approve', json={})
    assert r.status_code == 200 and r.json()['pseudo_id'] == 'A-C03', r.text
    assert ('approve', KC_UID, 'counselor') in calls['kc']
    approve_sql = [p for s, p in calls['sql'] if 'approve_staff_signup(' in s][0]
    assert approve_sql == (SID, ADMIN.user_id)


def test_approver_approval_notifies_existing_approvers(client):
    tc, calls, _ = client
    calls['signup'] = signup('approver')
    assert tc.post(f'/api/staff-signups/{SID}/approve', json={}).status_code == 200
    roles = [p[0] for s, p in calls['sql'] if 'SELECT user_id FROM users WHERE role' in s]
    assert 'approver' in roles and 'data_admin' in roles


def test_approve_db_failure_reverts_keycloak(client):
    tc, calls, _ = client
    calls['signup'] = signup()
    calls['db_error'] = True
    assert tc.post(f'/api/staff-signups/{SID}/approve', json={}).status_code == 500
    assert ('revert', KC_UID, 'counselor') in calls['kc']


def test_reject_deletes_account_and_record(client):
    tc, calls, _ = client
    calls['signup'] = signup()
    assert tc.post(f'/api/staff-signups/{SID}/reject', json={}).status_code == 200
    assert ('delete', KC_UID) in calls['kc']
    assert any('DELETE FROM staff_signups' in s for s, _ in calls['sql'])


def test_missing_signup_404(client):
    tc, calls, _ = client
    assert tc.post(f'/api/staff-signups/{SID}/approve', json={}).status_code == 404
    assert not calls['kc']


@pytest.mark.parametrize('role', ['counselor', 'approver'])
def test_only_data_admin(client, role):
    tc, calls, who = client
    who['principal'] = Principal(user_id='x', pseudo_id='A-C01', role=role)
    calls['signup'] = signup()
    assert tc.get('/api/staff-signups').status_code == 403
    assert tc.post(f'/api/staff-signups/{SID}/approve', json={}).status_code == 403
    assert tc.post(f'/api/staff-signups/{SID}/reject', json={}).status_code == 403
    assert not calls['kc']
    who['principal'] = None
    assert tc.get('/api/staff-signups').status_code == 401


class FakeKC:
    """Keycloak 관리 API 흉내: 사용자 1명."""
    def __init__(self, enabled=False, roles=(), group_roles=('counselor',)):
        self.enabled, self.roles, self.group_roles, self.log = enabled, set(roles), set(group_roles), []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def get(self, url, params=None):
        self.log.append(('GET', url))
        if url.endswith('/groups'):
            return SimpleNamespace(status_code=200, json=lambda: [{'id': 'g1', 'name': params['search']}])
        if url.endswith('/composite'):
            return SimpleNamespace(status_code=200, json=lambda: [{'name': r} for r in self.roles | {'default-roles-matchmaking'}])
        return SimpleNamespace(status_code=200, json=lambda: {'id': KC_UID, 'username': 'newstaff1', 'email': 'e', 'enabled': self.enabled})
    def put(self, url, json=None):
        self.log.append(('PUT', url, json))
        if url.endswith('/groups/g1'):
            self.roles |= self.group_roles
        elif json is not None:
            self.enabled = json['enabled']
        return SimpleNamespace(status_code=204)
    def delete(self, url):
        self.log.append(('DELETE', url))
        if '/groups/' in url:
            self.roles -= self.group_roles
        return SimpleNamespace(status_code=204)
    def post(self, url, json):
        self.log.append(('POST', url, json))
        return SimpleNamespace(status_code=201, headers={'Location': f'http://kc/users/{KC_UID}'}, json=lambda: {})


def use(monkeypatch, kc):
    monkeypatch.setattr(keycloak_admin, '_client', lambda: kc)
    monkeypatch.setattr(keycloak_admin, '_base', lambda: 'http://kc')


def test_kc_create_pending_is_disabled_without_groups(monkeypatch):
    kc = FakeKC(); use(monkeypatch, kc)
    assert keycloak_admin.create_staff_pending('newstaff1', PASSWORD, 'e@example.test', '가상') == KC_UID
    rep = kc.log[0][2]
    assert rep['enabled'] is False and 'groups' not in rep and 'realmRoles' not in rep


def test_kc_approve_enables_with_full_representation(monkeypatch):
    kc = FakeKC(); use(monkeypatch, kc)
    keycloak_admin.approve_staff(KC_UID, 'counselor')
    assert kc.enabled and kc.roles == {'counselor'}
    full = [x for x in kc.log if x[0] == 'PUT' and x[2]]
    assert full[0][2]['username'] == 'newstaff1' and full[0][2]['enabled'] is True


@pytest.mark.parametrize('kc,reason', [(FakeKC(enabled=True), 'not_pending_account'),
                                       (FakeKC(roles=('member',)), 'not_pending_account'),
                                       (FakeKC(group_roles=('counselor', 'data_admin')), 'unexpected_roles')])
def test_kc_approve_refuses_non_pending_or_wrong_roles(monkeypatch, kc, reason):
    use(monkeypatch, kc)
    with pytest.raises(keycloak_admin.KeycloakAdminError, match=reason):
        keycloak_admin.approve_staff(KC_UID, 'counselor')
    if reason == 'unexpected_roles':
        assert not kc.enabled and 'data_admin' not in kc.roles


def test_kc_approve_rejects_data_admin_role(monkeypatch):
    use(monkeypatch, FakeKC())
    with pytest.raises(keycloak_admin.KeycloakAdminError, match='role_not_allowed'):
        keycloak_admin.approve_staff(KC_UID, 'data_admin')


def test_kc_delete_pending_refuses_active_staff(monkeypatch):
    use(monkeypatch, FakeKC(enabled=True, roles=('counselor',)))
    with pytest.raises(keycloak_admin.KeycloakAdminError, match='not_pending_account'):
        keycloak_admin.delete_pending_staff(KC_UID)
    kc = FakeKC(); use(monkeypatch, kc)
    assert keycloak_admin.delete_pending_staff(KC_UID) == 'deleted' and ('DELETE', f'http://kc/users/{KC_UID}') in kc.log
