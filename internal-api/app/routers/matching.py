
import uuid
from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import Principal, Role
from .. import audit, db, transfer_client
from ..auth.session import member_via_transfer, staff_via_transfer, require, require_csrf, require_service
from .business import _age, _iso, _public_label, _member_in_scope

router=APIRouter(prefix='/api',tags=['paid-matching'])

class Strict(BaseModel):
    model_config=ConfigDict(extra='forbid')

class Empty(Strict):
    pass


def active_member(conn,user_id):
    row=conn.execute("""SELECT m.* FROM members m JOIN users u ON u.user_id=m.user_id
        WHERE m.user_id=%s AND m.status='active' AND u.active AND u.role='member'""",(user_id,)).fetchone()
    if row is None:raise GateError(ErrorCode.ACCESS_DENIED,'member_not_active')
    return row


def directory_card(row):
    age=_age(row['birth_date'])
    return {'member_id':str(row['member_id']),'user_id':str(row['user_id']),
        'pseudo_id':_public_label(row['birth_date'],row['education_level'])[:40],
        'age_band':f'만 {age}세' if age is not None else '비공개',
        'job_group':'비공개','introduction':'직원이 소개한 회원입니다. 상세 자료는 별도 공개 동의 후 확인합니다.',
        'eligible':bool(row['education_verified'])}


@router.post('/internal/matching-directory')
def directory(body: Empty,request: Request,member: Principal=Depends(member_via_transfer)):
    with db.connection() as conn:
        owner=active_member(conn,member.user_id)
        rows=conn.execute("""SELECT cm.* FROM introductions i JOIN members cm ON cm.member_id=i.counterpart_member_id
            JOIN users u ON u.user_id=cm.user_id
            WHERE i.member_id=%s AND cm.status='active' AND u.active AND u.role='member'
            ORDER BY cm.member_id LIMIT 100""",(owner['member_id'],)).fetchall()
    audit.allow(request,target_type='matching_directory')
    return {'self':directory_card(owner),'items':[directory_card(row) for row in rows]}


class Disclosure(Strict):
    member_id: uuid.UUID
    recipient_id: uuid.UUID
    grant_id: uuid.UUID
    match_id: uuid.UUID
    scopes: list[Literal['profile','photo','contact','education','employment','income','marital_status']]=Field(min_length=1,max_length=7)
    expires_at: AwareDatetime
    purpose: Literal['introduction']


@router.post('/internal/matching-disclosures')
def disclosures(body: Disclosure,request: Request,member: Principal=Depends(member_via_transfer)):
    if str(body.recipient_id)!=member.user_id or body.expires_at<=datetime.now(timezone.utc):
        raise GateError(ErrorCode.ACCESS_DENIED,'matching_context_invalid')
    with db.connection() as conn:
        owner=active_member(conn,member.user_id)
        peer=conn.execute("""SELECT cm.* FROM introductions i JOIN members cm ON cm.member_id=i.counterpart_member_id
            JOIN users u ON u.user_id=cm.user_id
            WHERE i.member_id=%s AND cm.member_id=%s AND cm.status='active' AND u.active AND u.role='member'""",
            (owner['member_id'],body.member_id)).fetchone()
        if not peer or not owner['education_verified'] or not peer['education_verified']:
            raise GateError(ErrorCode.ACCESS_DENIED,'matching_peer_not_eligible')
        reviews=conn.execute("""SELECT kind,result,reviewed_at FROM (
            SELECT e.kind,r.result,r.created_at AS reviewed_at,
                row_number() OVER (PARTITION BY e.kind ORDER BY r.created_at DESC,r.file_id DESC) AS latest
            FROM evidence_files e JOIN evidence_reviews r ON r.file_id=e.file_id
            WHERE e.member_id=%s) reviewed WHERE latest=1""",(peer['member_id'],)).fetchall()
    reviewed={r['kind']:r['reviewed_at'] for r in reviews if r['result']=='passed'}
    fields=[]
    def add(scope,label,value,kind):
        if scope in body.scopes and reviewed.get(kind):
            fields.append({'scope':scope,'label':label,'value':value[:300],
                           'review_status':'reviewed','reviewed_at':_iso(reviewed[kind])})
    add('profile','공개 소개',_public_label(peer['birth_date'],peer['education_level']),'education')
    if peer['education_verified']:
        add('education','학력 확인',peer['education_level'] or '학력 자료 검토 완료','education')
    if peer['employment_verified']:
        add('employment','재직 확인','재직 자료 검토 완료 · '+(peer['job_group'] or '직군 비공개'),'employment')
    # No original documents, real name, school/company, phone or unreviewed claim is returned.
    # Contact/photo/income/marital_status stay unavailable until their review/release contract exists.
    audit.allow(request,target_type='matching_disclosure',target_id=str(body.match_id))
    return {'member_id':str(peer['member_id']),'fields':fields}


class StaffCheck(Strict):
    participant_user_ids: list[uuid.UUID]=Field(min_length=2,max_length=2)
    purpose: Literal['meeting_schedule','matching_overview']
    action: Literal['read','propose','confirm','cancel']


@router.post('/internal/matching-staff-checks')
def staff_check(body: StaffCheck,request: Request,staff: Principal=Depends(staff_via_transfer)):
    ids=[str(x) for x in body.participant_user_ids]
    if len(set(ids))!=2:raise GateError(ErrorCode.INVALID_REQUEST,'distinct_participants_required')
    with db.connection() as conn:
        first,second=[active_member(conn,who) for who in ids]
        relation=conn.execute('SELECT 1 FROM introductions WHERE member_id=%s AND counterpart_member_id=%s',
                              (first['member_id'],second['member_id'])).fetchone()
        if body.purpose=='meeting_schedule' and (not relation or not first['education_verified'] or not second['education_verified']):
            raise GateError(ErrorCode.ACCESS_DENIED,'meeting_participants_not_eligible')
        rows=conn.execute("""SELECT m.user_id FROM assignments a JOIN members m ON m.member_id=a.member_id
            WHERE a.user_id=%s AND m.user_id=ANY(%s::uuid[])""",(staff.user_id,ids)).fetchall()
    assigned=[str(r['user_id']) for r in rows]
    audit.allow(request,target_type='meeting_staff_check')
    return {'allowed':bool(assigned),'assigned_user_ids':assigned}


class ReleaseCheck(Strict):
    owner_id: uuid.UUID
    recipient_id: uuid.UUID
    member_id: uuid.UUID
    scopes: list[Literal['profile','education','employment']]=Field(min_length=1,max_length=3)
    requester_id: uuid.UUID


@router.post('/internal/matching-release-checks')
def release_check(body: ReleaseCheck,request: Request,claims: dict=Depends(require_service('transfer-api'))):
    with db.connection() as conn:
        owner=active_member(conn,str(body.owner_id))
        peer=active_member(conn,str(body.recipient_id))
        if str(owner['member_id'])!=str(body.member_id) or body.owner_id==body.recipient_id:
            raise GateError(ErrorCode.ACCESS_DENIED,'matching_release_subject_mismatch')
        relation=conn.execute('SELECT 1 FROM introductions WHERE member_id=%s AND counterpart_member_id=%s',
                              (owner['member_id'],peer['member_id'])).fetchone()
        assigned=conn.execute("""SELECT 1 FROM assignments a JOIN users u ON u.user_id=a.user_id
            WHERE a.member_id=%s AND a.user_id=%s AND u.active AND u.role='counselor'""",
            (owner['member_id'],body.requester_id)).fetchone()
        if not relation or not assigned or not owner['education_verified'] or not peer['education_verified']:
            raise GateError(ErrorCode.ACCESS_DENIED,'matching_release_not_eligible')
        reviews=conn.execute("""SELECT kind,result,reviewed_at FROM (
            SELECT e.kind,r.result,r.created_at AS reviewed_at,
                row_number() OVER (PARTITION BY e.kind ORDER BY r.created_at DESC,r.file_id DESC) AS latest
            FROM evidence_files e JOIN evidence_reviews r ON r.file_id=e.file_id
            WHERE e.member_id=%s) reviewed WHERE latest=1""",(owner['member_id'],)).fetchall()
    passed={r['kind']:r for r in reviews if r['result']=='passed'}
    definitions={'profile':('공개 소개',_public_label(owner['birth_date'],owner['education_level']),'education'),
                 'education':('학력 확인',owner['education_level'] or '학력 자료 검토 완료','education'),
                 'employment':('재직 확인','재직 자료 검토 완료 · '+(owner['job_group'] or '직군 비공개'),'employment')}
    fields=[]
    for scope in sorted(set(body.scopes)):
        label,value,kind=definitions[scope]
        if kind not in passed or (kind=='employment' and not owner['employment_verified']):
            raise GateError(ErrorCode.INVALID_STATE,'matching_release_review_required',message='선택한 공개 항목의 증빙 심사가 필요합니다.')
        fields.append({'scope':scope,'label':label,'value':value[:300],
                       'review_status':'reviewed','reviewed_at':_iso(passed[kind]['reviewed_at'])})
    audit.allow(request,target_type='matching_release_check',target_id=str(body.member_id))
    return {'member_id':str(body.member_id),'fields':fields}


@router.get('/matching/overview')
def matching_overview(request: Request,member_id: uuid.UUID | None=None,staff: Principal=Depends(require(Role.COUNSELOR))):
    selected=None
    if member_id:
        with db.connection() as conn:
            _member_in_scope(conn,staff,member_id)
            selected=conn.execute('SELECT user_id FROM members WHERE member_id=%s',(member_id,)).fetchone()['user_id']
        if not selected:return {'items':[],'data_source':'internal'}
    response=transfer_client.call(request,'GET','/api/matching/overview')
    if response.status_code!=200:return transfer_client.relay(response)
    body=response.json()
    if selected:body['items']=[i for i in body['items'] if str(selected) in (i['sender_id'],i['recipient_id'])]
    ids=list({item[key] for item in body['items'] for key in ('sender_id','recipient_id')})
    if ids:
        with db.connection() as conn:
            rows=conn.execute("""SELECT m.user_id,m.pseudo_id,m.name,m.birth_date,m.education_level,a.user_id AS assigned
                FROM members m LEFT JOIN assignments a ON a.member_id=m.member_id AND a.user_id=%s
                WHERE m.user_id=ANY(%s::uuid[])""",(staff.user_id,ids)).fetchall()
        labels={str(r['user_id']):(r['pseudo_id']+' '+r['name'] if r['assigned'] else
                    _public_label(r['birth_date'],r['education_level'])) for r in rows}
        for item in body['items']:
            item['label']=' ↔ '.join(labels.get(item[k],'소개 상대') for k in ('sender_id','recipient_id'))
            for grant in item['grants']:
                grant['owner_label']=labels.get(grant['owner_id'],'소개 상대')
                grant['recipient_label']=labels.get(grant['recipient_id'],'소개 상대')
    audit.allow(request,target_type='matching_overview')
    return body


class Preparation(Strict):
    grant_id: uuid.UUID
    scopes: list[Literal['profile','education','employment']]=Field(min_length=1,max_length=3)


@router.post('/matching/releases',status_code=201)
def prepare_matching_release(body: Preparation,request: Request,
                             staff: Principal=Depends(require(Role.COUNSELOR)),csrf=Depends(require_csrf)):
    return relay(request,'POST','/api/matching/releases',body.model_dump(mode='json'))


class Option(Strict):
    starts_at: AwareDatetime
    venue: str=Field(min_length=1,max_length=120)
    address: str=Field(min_length=1,max_length=240)

class Options(Strict):
    options: list[Option]=Field(min_length=1,max_length=3)


def relay(request,method,path,body=None):
    response=transfer_client.call(request,method,path,**({'json':body} if body is not None else {}))
    if response.status_code>=400:audit.deny(request,'meeting_upstream_denied')
    else:audit.allow(request,target_type='meeting_schedule')
    return transfer_client.relay(response)


@router.get('/matching/requests')
def staff_matches(request: Request,staff: Principal=Depends(require(Role.COUNSELOR))):
    response=transfer_client.call(request,'GET','/api/matching/requests')
    if response.status_code!=200:return transfer_client.relay(response)
    body=response.json()
    ids=list({item[key] for item in body['items'] for key in ('sender_id','recipient_id')})
    labels={}
    if ids:
        with db.connection() as conn:
            rows=conn.execute("""SELECT m.user_id,m.pseudo_id,m.name,m.birth_date,m.education_level,a.user_id AS assigned
                FROM members m LEFT JOIN assignments a ON a.member_id=m.member_id AND a.user_id=%s
                WHERE m.user_id=ANY(%s::uuid[])""",(staff.user_id,ids)).fetchall()
        labels={str(row['user_id']):(row['pseudo_id']+' '+row['name'] if row['assigned'] else
                    _public_label(row['birth_date'],row['education_level'])) for row in rows}
    for item in body['items']:
        item['label']=' ↔ '.join(labels.get(item[key],'소개 상대') for key in ('sender_id','recipient_id'))
    audit.allow(request,target_type='meeting_schedule_list')
    return body


@router.get('/matching/requests/{match_id}/meetings')
def meetings(match_id: uuid.UUID,request: Request,staff: Principal=Depends(require(Role.COUNSELOR))):
    return relay(request,'GET',f'/api/matching/requests/{match_id}/meetings')


@router.post('/matching/requests/{match_id}/meetings',status_code=201)
def propose(match_id: uuid.UUID,body: Options,request: Request,staff: Principal=Depends(require(Role.COUNSELOR)),
            csrf=Depends(require_csrf)):
    return relay(request,'POST',f'/api/matching/requests/{match_id}/meetings',body.model_dump(mode='json'))


@router.post('/matching/requests/{match_id}/meetings/{proposal_id}/confirm')
def confirm(match_id: uuid.UUID,proposal_id: uuid.UUID,body: Empty,request: Request,
            staff: Principal=Depends(require(Role.COUNSELOR)),csrf=Depends(require_csrf)):
    return relay(request,'POST',f'/api/matching/requests/{match_id}/meetings/{proposal_id}/confirm',{})


@router.post('/matching/requests/{match_id}/meetings/{proposal_id}/cancel')
def cancel(match_id: uuid.UUID,proposal_id: uuid.UUID,body: Empty,request: Request,
           staff: Principal=Depends(require(Role.COUNSELOR)),csrf=Depends(require_csrf)):
    return relay(request,'POST',f'/api/matching/requests/{match_id}/meetings/{proposal_id}/cancel',{})
