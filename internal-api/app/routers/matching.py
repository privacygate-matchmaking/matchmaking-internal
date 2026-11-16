
import base64
import uuid
from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import Principal, Role
from .. import audit, db, evidence_rules, storage, transfer_client
from ..auth.session import member_via_transfer, staff_via_transfer, staff_or_admin_via_transfer, require, require_csrf, require_service
from .business import _age, _iso, _public_label, _member_in_scope, contact_like

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


def latest_passed(conn,member_id,kind):
    """그 종류 증빙의 최신 심사가 통과인지."""
    row=conn.execute("""SELECT r.result FROM evidence_files e JOIN evidence_reviews r ON r.file_id=e.file_id
        WHERE e.member_id=%s AND e.kind=%s ORDER BY r.created_at DESC LIMIT 1""",(member_id,kind)).fetchone()
    return bool(row) and row['result']=='passed'


def identity_passed(conn,member_id):
    """신분증(본인 확인) 최신 심사가 통과인지."""
    return latest_passed(conn,member_id,'identity')


def requirements(conn,row):
    """매칭 필수 조건: 신분증(본인 확인)·학력·프로필 사진 심사 통과."""
    return {'identity':identity_passed(conn,row['member_id']),'education':bool(row['education_verified']),
            'photo':latest_passed(conn,row['member_id'],'photo')}


def ready(conn,row):
    """매칭 자격: 필수 조건(신분증·학력·프로필 사진)이 모두 통과."""
    return all(requirements(conn,row).values())


# 소개 관계(후보 범위): 직원이 직접 소개한 쌍(introductions) 또는 성별이 다른 회원 쌍.
# 담당 직원이 달라도 후보가 된다. 상대가 활동 중·회원 계정 연결인지는 각 쿼리에서 따로 확인한다.
def pair_sql(a,b):
    return (f"(EXISTS (SELECT 1 FROM introductions i WHERE i.member_id={a}.member_id AND i.counterpart_member_id={b}.member_id)"
            f" OR ({a}.gender IS NOT NULL AND {b}.gender IS NOT NULL AND {a}.gender<>{b}.gender))")


def related(conn,member_id,counterpart_id):
    return conn.execute(f"""SELECT 1 FROM members x JOIN members y ON y.member_id=%s
        WHERE x.member_id=%s AND x.member_id<>y.member_id AND {pair_sql('x','y')}""",
        (str(counterpart_id),str(member_id))).fetchone() is not None


def intro_text(row):
    """후보 카드에 보이는 회원 본인의 소개글. 연락 수단이 섞여 있으면 보여 주지 않는다 (예전 자료 대비)."""
    text=' '.join((row['introduction'] or '').split())[:300]
    if not text:return '아직 소개글을 작성하지 않았습니다.'
    if contact_like(text):return '소개글을 확인 중입니다.'
    return text


def directory_card(row,eligible):
    age=_age(row['birth_date'])
    return {'member_id':str(row['member_id']),'user_id':str(row['user_id']),
        'pseudo_id':_public_label(row['birth_date'],row['education_level'])[:40],
        'age_band':f'만 {age}세' if age is not None else '비공개',
        'job_group':'비공개','introduction':intro_text(row),
        'height_cm':row['height_cm'],'weight_kg':row['weight_kg'],      # 본인 신고 값
        'eligible':bool(eligible)}


ALL_SCOPES=Literal['name','profile','photo','contact','education','employment','income','marital_status','property','documents']


def passed_results(conn,member_id):
    """종류별 최신 심사가 '통과'인 증빙과 그 공개 결과(요약·마스킹 사본)."""
    rows=conn.execute("""SELECT kind,reviewed_at,summary,masked_key,masked_hash,masked_type FROM (
        SELECT e.kind,r.result,r.created_at AS reviewed_at,res.summary,res.masked_key,res.masked_hash,res.masked_type,
            row_number() OVER (PARTITION BY e.kind ORDER BY r.created_at DESC,r.file_id DESC) AS latest
        FROM evidence_files e JOIN evidence_reviews r ON r.file_id=e.file_id
        LEFT JOIN evidence_results res ON res.file_id=e.file_id
        WHERE e.member_id=%s) x WHERE latest=1 AND result='passed'""",(member_id,)).fetchall()
    return {r['kind']:r for r in rows}


def text_value(scope,member,passed):
    """화면 열람·자료에 공통으로 쓰는 한 줄 (원값 없이 검토 결과만). 없으면 None."""
    kind=evidence_rules.SCOPE_KIND[scope]
    if kind not in passed:return None
    if scope=='profile':return _public_label(member['birth_date'],member['education_level'])
    if scope=='education':return (member['education_level'] or '학력 자료 검토 완료') if member['education_verified'] else None
    if scope=='employment':return '재직 자료 검토 완료 · '+(member['job_group'] or '직군 비공개') if member['employment_verified'] else None
    return passed[kind]['summary']


def attachment(row,name,label):
    """마스킹 사본을 자료 파일에 넣는 형식. 저장된 해시와 다르면 넣지 않는다 (사본 바꿔치기 방지)."""
    blob=storage.get(row['masked_key'])
    if storage.sha256_hex(blob)!=row['masked_hash']:
        raise GateError(ErrorCode.APPROVAL_MISMATCH,'masked_copy_hash_mismatch')
    ext='jpg' if row['masked_type']=='image/jpeg' else 'png'
    return {'name':f'{name}.{ext}','label':label,'media_type':row['masked_type'],'sha256':row['masked_hash'],
            'data_base64':base64.b64encode(blob).decode('ascii')}


@router.post('/internal/matching-directory')
def directory(body: Empty,request: Request,member: Principal=Depends(member_via_transfer)):
    with db.connection() as conn:
        owner=active_member(conn,member.user_id)
        rows=conn.execute(f"""SELECT cm.* FROM members me JOIN members cm ON cm.member_id<>me.member_id
            JOIN users u ON u.user_id=cm.user_id
            WHERE me.member_id=%s AND cm.status='active' AND u.active AND u.role='member' AND {pair_sql('me','cm')}
            ORDER BY cm.created_at,cm.member_id LIMIT 100""",(owner['member_id'],)).fetchall()
        cards={'self':{**directory_card(owner,ready(conn,owner)),'requirements':requirements(conn,owner)},
               'items':[directory_card(row,ready(conn,row)) for row in rows]}
    audit.allow(request,target_type='matching_directory')
    return cards


class Disclosure(Strict):
    member_id: uuid.UUID
    recipient_id: uuid.UUID
    grant_id: uuid.UUID
    match_id: uuid.UUID
    scopes: list[ALL_SCOPES]=Field(min_length=1,max_length=10)
    expires_at: AwareDatetime
    purpose: Literal['introduction']
    contact_ready: bool=False      # 중계가 확인: 만남 일정 확정 + 두 회원 모두 연락처 동의


@router.post('/internal/matching-disclosures')
def disclosures(body: Disclosure,request: Request,member: Principal=Depends(member_via_transfer)):
    """화면 열람용 검토 결과 (텍스트). 이름은 동의만으로, 연락처는 중계가 확인한 조건(일정 확정 + 상호 동의)과
    본인 확인(신분증 통과)·연락처 등록이 있을 때만 넣는다. 사진·문서 사본은 직원 요청 + 승인자 승인 자료로만 제공한다."""
    if str(body.recipient_id)!=member.user_id or body.expires_at<=datetime.now(timezone.utc):
        raise GateError(ErrorCode.ACCESS_DENIED,'matching_context_invalid')
    with db.connection() as conn:
        owner=active_member(conn,member.user_id)
        peer=conn.execute(f"""SELECT cm.* FROM members me JOIN members cm ON cm.member_id<>me.member_id
            JOIN users u ON u.user_id=cm.user_id
            WHERE me.member_id=%s AND cm.member_id=%s AND cm.status='active' AND u.active AND u.role='member'
              AND {pair_sql('me','cm')}""",
            (owner['member_id'],body.member_id)).fetchone()
        if not peer or not ready(conn,owner) or not ready(conn,peer):
            raise GateError(ErrorCode.ACCESS_DENIED,'matching_peer_not_eligible')
        passed=passed_results(conn,peer['member_id'])
    labels={'profile':'공개 소개','education':'학력 확인','employment':'재직 확인','income':'소득 구간',
            'marital_status':'혼인관계','property':'부동산'}
    fields=[]
    show_name='name' in body.scopes and peer['name'] and 'identity' in passed
    for scope in evidence_rules.TEXT_SCOPES:
        if scope not in body.scopes:continue
        value=text_value(scope,peer,passed)
        if value:
            if scope=='profile' and show_name:value=value.replace('소개 상대',peer['name'],1)
            fields.append({'scope':scope,'label':labels[scope],'value':value[:300],'review_status':'reviewed',
                           'reviewed_at':_iso(passed[evidence_rules.SCOPE_KIND[scope]]['reviewed_at'])})
    if show_name and 'profile' not in body.scopes:
        fields.insert(0,{'scope':'name','label':'이름','value':peer['name'][:300],'review_status':'reviewed',
                         'reviewed_at':_iso(passed['identity']['reviewed_at'])})
    if 'contact' in body.scopes and body.contact_ready and 'identity' in passed:
        parts=[p for p in (peer['contact_phone'] and '전화 '+peer['contact_phone'],
                           peer['contact_email'] and '이메일 '+peer['contact_email']) if p]
        if parts:
            fields.append({'scope':'contact','label':'연락처','value':' · '.join(parts)[:300],'review_status':'reviewed',
                           'reviewed_at':_iso(passed['identity']['reviewed_at'])})
    audit.allow(request,target_type='matching_disclosure',target_id=str(body.match_id))
    return {'member_id':str(peer['member_id']),'fields':fields}


class StaffCheck(Strict):
    participant_user_ids: list[uuid.UUID]=Field(min_length=2,max_length=2)
    purpose: Literal['meeting_schedule','matching_overview']
    action: Literal['read','propose','confirm','cancel','end']


@router.post('/internal/matching-staff-checks')
def staff_check(body: StaffCheck,request: Request,staff: Principal=Depends(staff_via_transfer)):
    ids=[str(x) for x in body.participant_user_ids]
    if len(set(ids))!=2:raise GateError(ErrorCode.INVALID_REQUEST,'distinct_participants_required')
    with db.connection() as conn:
        first,second=[active_member(conn,who) for who in ids]
        relation=related(conn,first['member_id'],second['member_id'])
        if body.purpose=='meeting_schedule' and (not relation or not ready(conn,first) or not ready(conn,second)):
            raise GateError(ErrorCode.ACCESS_DENIED,'meeting_participants_not_eligible')
        rows=conn.execute("""SELECT m.user_id FROM assignments a JOIN members m ON m.member_id=a.member_id
            WHERE a.user_id=%s AND m.user_id=ANY(%s::uuid[])""",(staff.user_id,ids)).fetchall()
    assigned=[str(r['user_id']) for r in rows]
    audit.allow(request,target_type='meeting_staff_check')
    return {'allowed':bool(assigned),'assigned_user_ids':assigned}


class MemberScopeCheck(Strict):
    user_id: uuid.UUID


@router.post('/internal/member-scope-checks')
def member_scope_check(body: MemberScopeCheck,request: Request,staff: Principal=Depends(staff_or_admin_via_transfer)):
    """중계가 회원 이용권 정보를 직원에게 주기 전 확인: 총관리자이거나 그 회원의 담당 상담 직원인지."""
    with db.connection() as conn:
        row=conn.execute("""SELECT 1 FROM members m WHERE m.user_id=%s AND (%s='data_admin' OR EXISTS (
            SELECT 1 FROM assignments a WHERE a.member_id=m.member_id AND a.user_id=%s))""",
            (str(body.user_id),staff.role,staff.user_id)).fetchone()
    audit.allow(request,target_type='member_scope_check',reason='allowed' if row else 'denied')
    return {'allowed':bool(row)}


class ReleaseCheck(Strict):
    owner_id: uuid.UUID
    recipient_id: uuid.UUID
    member_id: uuid.UUID
    scopes: list[ALL_SCOPES]=Field(min_length=1,max_length=10)
    requester_id: uuid.UUID


RELEASE_LABELS={'name':'이름','profile':'공개 소개','education':'학력 확인','employment':'재직 확인','income':'소득 구간',
                'marital_status':'혼인관계','property':'부동산','photo':'프로필 사진',
                'documents':'검토·마스킹된 문서 사본','contact':'연락처'}


@router.post('/internal/matching-release-checks')
def release_check(body: ReleaseCheck,request: Request,claims: dict=Depends(require_service('transfer-api'))):
    """반출 자료에 넣을 항목을 현재 심사 결과로 다시 만든다 (요청·승인·다운로드 때마다 호출).
    연락처: 상호 동의·일정 확정은 중계가 확인하고, 여기서는 담당 직원·본인 확인(신분증 통과)·연락처 등록을 확인한다."""
    with db.connection() as conn:
        owner=active_member(conn,str(body.owner_id))
        peer=active_member(conn,str(body.recipient_id))
        if str(owner['member_id'])!=str(body.member_id) or body.owner_id==body.recipient_id:
            raise GateError(ErrorCode.ACCESS_DENIED,'matching_release_subject_mismatch')
        relation=related(conn,owner['member_id'],peer['member_id'])
        assigned=conn.execute("""SELECT 1 FROM assignments a JOIN users u ON u.user_id=a.user_id
            WHERE a.member_id=%s AND a.user_id=%s AND u.active AND u.role='counselor'""",
            (owner['member_id'],body.requester_id)).fetchone()
        if not relation or not assigned or not ready(conn,owner) or not ready(conn,peer):
            raise GateError(ErrorCode.ACCESS_DENIED,'matching_release_not_eligible')
        passed=passed_results(conn,owner['member_id'])
        need=lambda: GateError(ErrorCode.INVALID_STATE,'matching_release_review_required',message='선택한 공개 항목의 증빙 심사가 필요합니다.')
        scopes=sorted(set(body.scopes))
        fields=[]
        for scope in scopes:
            field={'scope':scope,'label':RELEASE_LABELS[scope],'review_status':'reviewed'}
            if scope in evidence_rules.TEXT_SCOPES:
                value=text_value(scope,owner,passed)
                if not value:raise need()
                if scope=='profile' and 'name' in scopes and owner['name']:value=value.replace('소개 상대',owner['name'],1)
                field.update(value=value[:300],reviewed_at=_iso(passed[evidence_rules.SCOPE_KIND[scope]]['reviewed_at']))
            elif scope=='name':
                if 'identity' not in passed or not owner['name']:
                    raise GateError(ErrorCode.INVALID_STATE,'name_identity_required',message='이름 공개 전 본인 확인(신분증) 심사가 필요합니다.')
                field.update(value=owner['name'][:300],reviewed_at=_iso(passed['identity']['reviewed_at']))
            elif scope=='photo':
                row=passed.get('photo')
                if not row or not row['masked_key']:raise need()
                field.update(value=row['summary'][:300],reviewed_at=_iso(row['reviewed_at']),
                             attachments=[attachment(row,'profile-photo','프로필 사진')])
            elif scope=='documents':
                kinds=[evidence_rules.SCOPE_KIND[s] for s in scopes if s in ('education','employment','income','marital_status','property')]
                rows=[(k,passed[k]) for k in dict.fromkeys(kinds) if k in passed and passed[k]['masked_key']]
                if not rows:
                    raise GateError(ErrorCode.INVALID_STATE,'matching_release_document_missing',
                                    message='문서 사본은 함께 선택한 항목(학력·재직·소득·혼인·부동산)의 마스킹 사본이 있어야 합니다.')
                field.update(value='검토·마스킹 사본 '+str(len(rows))+'건 ('+', '.join(evidence_rules.KIND_KO[k] for k,_ in rows)+') · 원본 아님',
                             reviewed_at=_iso(max(r['reviewed_at'] for _,r in rows)),
                             attachments=[attachment(r,f'{k}-masked',evidence_rules.KIND_KO[k]+' 마스킹 사본') for k,r in rows])
            elif scope=='contact':
                if 'identity' not in passed:
                    raise GateError(ErrorCode.INVALID_STATE,'contact_identity_required',message='연락처 전달 전 본인 확인(신분증) 심사가 필요합니다.')
                parts=[p for p in (owner['contact_phone'] and '전화 '+owner['contact_phone'],
                                   owner['contact_email'] and '이메일 '+owner['contact_email']) if p]
                if not parts:raise GateError(ErrorCode.INVALID_STATE,'contact_missing',message='회원 연락처가 등록되어 있지 않습니다.')
                field.update(value=' · '.join(parts)[:300],reviewed_at=_iso(passed['identity']['reviewed_at']))
            fields.append(field)
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
    scopes: list[ALL_SCOPES]=Field(min_length=1,max_length=10)


@router.post('/matching/releases',status_code=201)
def prepare_matching_release(body: Preparation,request: Request,
                             staff: Principal=Depends(require(Role.COUNSELOR)),csrf=Depends(require_csrf)):
    return relay(request,'POST','/api/matching/releases',body.model_dump(mode='json'))


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


@router.post('/matching/requests/{match_id}/meetings/{proposal_id}/confirm')
def confirm(match_id: uuid.UUID,proposal_id: uuid.UUID,body: Empty,request: Request,
            staff: Principal=Depends(require(Role.COUNSELOR)),csrf=Depends(require_csrf)):
    return relay(request,'POST',f'/api/matching/requests/{match_id}/meetings/{proposal_id}/confirm',{})


@router.post('/matching/requests/{match_id}/end')
def end_match(match_id: uuid.UUID,body: Empty,request: Request,
              staff: Principal=Depends(require(Role.COUNSELOR)),csrf=Depends(require_csrf)):
    """담당 상담 직원의 관계 종료 (중계가 담당 범위를 다시 확인)."""
    return relay(request,'POST',f'/api/matching/requests/{match_id}/end',{})


@router.post('/matching/requests/{match_id}/meetings/{proposal_id}/cancel')
def cancel(match_id: uuid.UUID,proposal_id: uuid.UUID,body: Empty,request: Request,
           staff: Principal=Depends(require(Role.COUNSELOR)),csrf=Depends(require_csrf)):
    return relay(request,'POST',f'/api/matching/requests/{match_id}/meetings/{proposal_id}/cancel',{})
