"""Internal HTTP contracts against a SQLite test adapter, not a production DB test."""
import sqlite3
import re
from contextlib import contextmanager
from datetime import date,datetime,timezone,timedelta
from types import SimpleNamespace
from uuid import uuid4
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from privacygate.errors import ErrorCode,GateError
from privacygate.audit import AuditWriter
from privacygate.web import install,assert_all_routes_guarded
from app import db,audit,transfer_client
from app.auth import session
from app.routers import business,matching

B='22222222-2222-4222-8222-222222222201'
C='22222222-2222-4222-8222-222222222202'
A='11111111-1111-4111-8111-111111111101'
M='bbbbbbbb-0000-4000-8000-000000000003'
N='bbbbbbbb-0000-4000-8000-000000000001'

class Result:
    def __init__(self,cursor):self.cursor=cursor
    def clean(self,row):
        if row is None:return None
        row=dict(row)
        if row.get('birth_date'):row['birth_date']=date.fromisoformat(row['birth_date'])
        for key in ('reviewed_at','expires_at'):
            if row.get(key):row[key]=datetime.fromisoformat(row[key])
        return row
    def fetchone(self):return self.clean(self.cursor.fetchone())
    def fetchall(self):return [self.clean(row) for row in self.cursor.fetchall()]

class Connection:
    def __init__(self):
        self.sql=sqlite3.connect(':memory:',check_same_thread=False)
        self.sql.row_factory=sqlite3.Row
        self.sql.create_function('now',0,lambda:datetime.now(timezone.utc).isoformat())
        self.sql.executescript("""
        CREATE TABLE users(user_id TEXT,pseudo_id TEXT,role TEXT,active INT);
        CREATE TABLE members(member_id TEXT,user_id TEXT,status TEXT,pseudo_id TEXT,name TEXT,birth_date TEXT,
            education_level TEXT,education_verified INT,employment_verified INT,job_group TEXT);
        CREATE TABLE introductions(member_id TEXT,counterpart_member_id TEXT);
        CREATE TABLE assignments(user_id TEXT,member_id TEXT);
        CREATE TABLE evidence_files(file_id TEXT,member_id TEXT,kind TEXT);
        CREATE TABLE evidence_reviews(file_id TEXT,result TEXT,created_at TEXT);
        CREATE TABLE consents(consent_id TEXT,member_id TEXT,counterpart_member_id TEXT,item TEXT,purpose TEXT,expires_at TEXT,revoked_at TEXT);
        """)
        self.sql.executemany('INSERT INTO users VALUES (?,?,?,1)',[(B,'A-003','member'),(C,'A-001','member'),(A,'A-C01','counselor')])
        for mid,who in ((M,B),(N,C)):
            self.sql.execute('INSERT INTO members VALUES (?,?,?,?,?,?,?,?,?,?)',
                (mid,who,'active','ADMIN-ONLY-CODE','SECRET-NAME','1995-01-01','4년제 대졸',1,1,'연구'))
        self.sql.executemany('INSERT INTO introductions VALUES (?,?)',[(M,N),(N,M)])
        self.sql.execute('INSERT INTO assignments VALUES (?,?)',(A,M))
        self.sql.execute('INSERT INTO evidence_files VALUES (?,?,?)',('education-file',N,'education'))
        self.sql.execute('INSERT INTO evidence_reviews VALUES (?,?,?)',('education-file','passed',datetime.now(timezone.utc).isoformat()))
    def execute(self,sql,params=()):
        params=list(params)
        if 'ANY(%s::uuid[])' in sql:
            ids=params.pop();sql=sql.replace('=ANY(%s::uuid[])',' IN ('+','.join('?' for _ in ids)+')');params.extend(ids)
        sql=sql.replace('%s','?')
        return Result(self.sql.execute(sql,[str(x) if not isinstance(x,(int,float,type(None))) else x for x in params]))

@pytest.fixture
def client(tmp_path,monkeypatch):
    conn=Connection()
    @contextmanager
    def connection():yield conn
    monkeypatch.setattr(db,'connection',connection)
    monkeypatch.setattr(audit,'allow',lambda *a,**k:None)
    monkeypatch.setattr(audit,'deny',lambda *a,**k:None)
    class Verifier:
        def verify(self,token):
            entries={'service':('svc','transfer-api',[]),'B':(B,'external-web',['member']),
                     'staff':(A,'internal-web',['counselor'])}
            if token not in entries:raise GateError(ErrorCode.AUTH_REQUIRED,'invalid_token')
            sub,azp,roles=entries[token]
            return {'sub':sub,'azp':azp,'realm_access':{'roles':roles}}
    monkeypatch.setattr(session,'service_verifier',lambda:Verifier())
    # service_guard captured the original verifier factory at import time.
    # Replace its issuer/JWKS provider, retaining the actual service guard logic.
    from app.auth import oidc
    monkeypatch.setattr(oidc,'discovery',lambda:{'issuer':'test','jwks_uri':'test'})
    monkeypatch.setattr(oidc,'get_settings',lambda:SimpleNamespace(api_audience='internal-api'))
    monkeypatch.setattr(oidc,'_cache',{'svc':Verifier()})
    monkeypatch.setattr(session,'get_settings',lambda:SimpleNamespace(app_base_url='https://testserver'))
    app=FastAPI();install(app,AuditWriter('test-internal',str(tmp_path/'audit.json')))
    app.include_router(matching.router);app.include_router(business.router)
    assert_all_routes_guarded(app)
    with TestClient(app,base_url='https://testserver') as tc:yield tc,conn,app


def headers(token='B'):
    return {'Authorization':'Bearer service','X-User-Token':token}


def release_body():
    return {'owner_id':B,'recipient_id':C,'member_id':M,'requester_id':A,'scopes':['education']}


def test_matching_release_requires_actual_owner_review_and_assignment(client):
    tc,conn,_=client
    body=release_body()
    assert tc.post('/api/internal/matching-release-checks',headers=headers(),json=body).status_code==409
    conn.execute('INSERT INTO evidence_files VALUES (%s,%s,%s)',('owner-education',M,'education'))
    conn.execute('INSERT INTO evidence_reviews VALUES (%s,%s,%s)',('owner-education','passed',datetime.now(timezone.utc).isoformat()))
    r=tc.post('/api/internal/matching-release-checks',headers=headers(),json=body)
    assert r.status_code==200,r.text
    assert [f['scope'] for f in r.json()['fields']]==['education']
    assert 'SECRET-NAME' not in r.text and 'ADMIN-ONLY-CODE' not in r.text
    conn.execute('DELETE FROM assignments')
    assert tc.post('/api/internal/matching-release-checks',headers=headers(),json=body).status_code==403


@pytest.mark.parametrize('fault',['member_uuid','staff_role','staff_inactive','peer_inactive','unintroduced','unsupported'])
def test_matching_release_rejects_invalid_business_context(client,fault):
    tc,conn,_=client;body=release_body()
    if fault=='member_uuid':body['member_id']=N
    if fault=='staff_role':conn.execute("UPDATE users SET role='approver' WHERE user_id=%s",(A,))
    if fault=='staff_inactive':conn.execute('UPDATE users SET active=0 WHERE user_id=%s',(A,))
    if fault=='peer_inactive':conn.execute("UPDATE members SET status='withdraw_pending' WHERE member_id=%s",(N,))
    if fault=='unintroduced':conn.execute('DELETE FROM introductions')
    if fault=='unsupported':body['scopes']=['contact']
    assert tc.post('/api/internal/matching-release-checks',headers=headers(),json=body).status_code in (403,422)


def test_matching_release_service_auth_is_required(client):
    tc,_,_=client
    assert tc.post('/api/internal/matching-release-checks',json=release_body()).status_code==401


def test_staff_release_bff_requires_explicit_scopes_and_csrf(client,monkeypatch):
    tc,_,app=client
    from privacygate.policy import Principal
    from fastapi import Request
    def current(request: Request):
        request.state.csrf_token='csrf'
        return Principal(A,'A-C01','counselor')
    app.dependency_overrides[session.current_principal]=current
    calls=[]
    def call(request,method,path,**kwargs):
        calls.append((method,path,kwargs));return httpx.Response(201,json={'request_status':'pending'})
    monkeypatch.setattr(transfer_client,'call',call)
    body={'grant_id':str(uuid4()),'scopes':['education']}
    assert tc.post('/api/matching/releases',json=body).status_code==403 and not calls
    h={'Origin':'https://testserver','X-CSRF-Token':'csrf'}
    assert tc.post('/api/matching/releases',json={**body,'owner_id':B},headers=h).status_code==422 and not calls
    assert tc.post('/api/matching/releases',json=body,headers=h).status_code==201
    assert calls==[('POST','/api/matching/releases',{'json':body})]


@pytest.mark.parametrize('role',['counselor','approver'])
def test_export_metadata_hides_nonassigned_member_names_in_sql(client,monkeypatch,role):
    _,conn,_=client
    from app.routers import transfer
    from privacygate.policy import Principal
    class Queries:
        def execute(self,sql,params):
            params=dict(params);ids=params.pop('ids')
            for i,value in enumerate(ids):params['id'+str(i)]=value
            sql=sql.replace('::text','').replace('ANY(%(ids)s)','('+','.join(':id'+str(i) for i in range(len(ids)))+')')
            sql=sql.replace('= (','IN (').replace('= ANY','IN')
            sql=re.sub(r'%\((\w+)\)s',r':\1',sql)
            return Result(conn.sql.execute(sql,params))
    @contextmanager
    def connection():yield Queries()
    monkeypatch.setattr(db,'connection',connection)
    items=[{'requester_id':A,'member_id':M,'recipient_id':C}]
    transfer._with_pseudo_ids(items,Principal(A,'A-C01',role))
    assert items[0]['member_name']=='SECRET-NAME'
    if role=='counselor':
        assert 'recipient_name' not in items[0]
        assert items[0]['recipient_pseudo_id']=='소개 상대'
    else:assert items[0]['recipient_name']=='SECRET-NAME'


def test_directory_is_introduced_and_omits_admin_identity(client):
    tc,conn,_=client
    response=tc.post('/api/internal/matching-directory',json={},headers=headers())
    assert response.status_code==200,response.text
    assert response.json()['items'][0]['member_id']==N
    assert 'ADMIN-ONLY-CODE' not in response.text and 'SECRET-NAME' not in response.text
    conn.execute('DELETE FROM introductions')
    assert tc.post('/api/internal/matching-directory',json={},headers=headers()).json()['items']==[]


def test_directory_does_not_invent_login_id_for_unlinked_member(client):
    tc,conn,_=client;conn.execute('UPDATE members SET user_id=NULL WHERE member_id=%s',(N,))
    assert tc.post('/api/internal/matching-directory',json={},headers=headers()).json()['items']==[]


def test_directory_requires_service_and_member_tokens(client):
    tc,_,_=client
    assert tc.post('/api/internal/matching-directory',json={}).status_code==401
    assert tc.post('/api/internal/matching-directory',json={},headers=headers('staff')).status_code==403


def disclosure_body():
    return {'member_id':N,'recipient_id':B,'match_id':str(uuid4()),'grant_id':str(uuid4()),
        'scopes':['education','contact','employment'],'expires_at':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),
        'purpose':'introduction'}


def test_disclosures_only_return_requested_actually_reviewed_text(client):
    tc,_,_=client
    response=tc.post('/api/internal/matching-disclosures',headers=headers(),json=disclosure_body())
    assert response.status_code==200,response.text
    assert [f['scope'] for f in response.json()['fields']]==['education']
    assert 'SECRET-NAME' not in response.text and 'contact_phone' not in response.text


@pytest.mark.parametrize('fault',['recipient','expired','unintroduced','inactive','education'])
def test_disclosures_reject_invalid_context(client,fault):
    tc,conn,_=client;body=disclosure_body()
    if fault=='recipient':body['recipient_id']=C
    if fault=='expired':body['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    if fault=='unintroduced':conn.execute('DELETE FROM introductions')
    if fault=='inactive':conn.execute("UPDATE members SET status='withdraw_pending' WHERE member_id=%s",(N,))
    if fault=='education':conn.execute('UPDATE members SET education_verified=0 WHERE member_id=%s',(M,))
    assert tc.post('/api/internal/matching-disclosures',headers=headers(),json=body).status_code==403


def check_body():return {'participant_user_ids':[B,C],'purpose':'meeting_schedule','action':'confirm'}


def test_staff_scope_only_returns_actual_assigned_participant(client):
    tc,_,_=client
    r=tc.post('/api/internal/matching-staff-checks',headers=headers('staff'),json=check_body())
    assert r.status_code==200,r.text
    assert r.json()=={'allowed':True,'assigned_user_ids':[B]}


@pytest.mark.parametrize('fault',['role','inactive','unassigned','peer_inactive','duplicate'])
def test_staff_scope_checks_current_authority(client,fault):
    tc,conn,_=client;body=check_body()
    if fault=='role':conn.execute("UPDATE users SET role='approver' WHERE user_id=%s",(A,))
    if fault=='inactive':conn.execute('UPDATE users SET active=0 WHERE user_id=%s',(A,))
    if fault=='unassigned':conn.execute('DELETE FROM assignments')
    if fault=='peer_inactive':conn.execute("UPDATE members SET status='withdraw_pending' WHERE member_id=%s",(N,))
    if fault=='duplicate':body['participant_user_ids']=[B,B]
    r=tc.post('/api/internal/matching-staff-checks',headers=headers('staff'),json=body)
    if fault=='unassigned':assert r.json()=={'allowed':False,'assigned_user_ids':[]}
    else:assert r.status_code in (403,422)


def test_legacy_matching_write_cannot_bypass_paid_flow(client):
    tc,_,_=client
    assert tc.post('/api/internal/my-matches',headers=headers(),json={'counterpart_member_id':N}).status_code==409
    assert tc.post(f'/api/internal/my-matches/{N}/cancel',headers=headers(),json={}).status_code==409
    assert tc.get('/api/internal/my-matches',headers=headers()).status_code==409


def test_staff_bff_requires_csrf_and_relays_fixed_path(client,monkeypatch):
    tc,_,app=client
    from privacygate.policy import Principal
    from fastapi import Request
    def current(request: Request):
        request.state.csrf_token='test-csrf'
        return Principal(A,'A-C01','counselor')
    app.dependency_overrides[session.current_principal]=current
    calls=[]
    def call(request,method,path,**kw):
        calls.append((method,path,kw));return httpx.Response(200,json={'confirmed':True})
    monkeypatch.setattr(transfer_client,'call',call)
    path=f'/api/matching/requests/{uuid4()}/meetings/{uuid4()}/confirm'
    assert tc.post(path,json={}).status_code==403 and not calls
    assert tc.post(path,json={},headers={'Origin':'https://testserver','X-CSRF-Token':'test-csrf'}).status_code==200
    assert calls==[('POST',path,{'json':{}})]



def test_generated_profile_separates_uuid_from_display_name():
    row={'member_id':M,'birth_date':date(1995,1,1),'education_level':'4년제 대졸','school':None,
         'major':None,'education_verified':True,'employment_verified':False,'job_group':'연구',
         'company':None,'height_cm':None,'weight_kg':None,'introduction':'합성 소개'}
    profile=business._detail_profile(row,'가상 이름')
    assert profile['schema_version']==2 and profile['member_id']==M
    assert profile['display_name']=='가상 이름' and 'member_pseudo_id' not in profile


def test_disclosure_response_uses_actual_member_uuid(client):
    tc,conn,_=client;cid=str(uuid4())
    expires=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    conn.execute('INSERT INTO consents VALUES (%s,%s,%s,%s,%s,%s,NULL)',(cid,M,N,'profile','introduction',expires))
    body={'member_id':M,'recipient_id':C,'consent_id':cid,'purpose':'introduction','item':'profile'}
    response=tc.post('/api/internal/disclosure-checks',headers=headers(),json=body)
    assert response.status_code==200,response.text
    assert response.json()['member_id']==M and response.json()['allowed'] is True
    assert 'member_pseudo_id' not in response.json() and 'SECRET-NAME' not in response.text
    body['member_id']=N
    assert tc.post('/api/internal/disclosure-checks',headers=headers(),json=body).json()=={'allowed':False}



def test_staff_list_labels_hide_non_assigned_member_name(client,monkeypatch):
    from privacygate.policy import Principal
    tc,_,app=client
    app.dependency_overrides[session.current_principal]=lambda:Principal(A,'A-C01','counselor')
    monkeypatch.setattr(transfer_client,'call',lambda *a,**kw:httpx.Response(200,json={
        'items':[{'match_id':str(uuid4()),'sender_id':B,'recipient_id':C,'status':'matched'}]}))
    r=tc.get('/api/matching/requests')
    assert r.status_code==200,r.text
    label=r.json()['items'][0]['label']
    assert label.count('SECRET-NAME')==1 and '소개 상대' in label



def test_newer_rejection_does_not_reuse_older_passed_result(client):
    tc,conn,_=client
    conn.execute('INSERT INTO evidence_files VALUES (%s,%s,%s)',('new-education',N,'education'))
    conn.execute('INSERT INTO evidence_reviews VALUES (%s,%s,%s)',('new-education','rejected',
                 (datetime.now(timezone.utc)+timedelta(seconds=1)).isoformat()))
    r=tc.post('/api/internal/matching-disclosures',headers=headers(),json=disclosure_body())
    assert r.status_code==200,r.text
    assert r.json()['fields']==[]
