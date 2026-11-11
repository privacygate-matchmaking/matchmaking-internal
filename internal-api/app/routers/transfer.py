"""반출(중계) 화면용 API. 브라우저 → internal-api → transfer-api.

브라우저는 transfer-api 주소도 서비스 인증정보도 모른다. internal-api 가 1차로 역할(과 담당 관계)을 확인하고,
서버에 보관한 직원 access token(aud=transfer-api, Keycloak 서명)을 붙여 transfer-api 로 전달한다.
transfer-api 는 그 토큰으로 신청자·승인자를 직접 확인하고 다시 검사한다 (이중 확인).
요청·응답 형식은 외부·중계 연동 계약 v0.5 를 따르며, 중계의 응답(오류 포함)을 그대로 돌려준다.
"""
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, File, Request, UploadFile
from privacygate.errors import ErrorCode, GateError
from privacygate.policy import Principal, Role
from pydantic import BaseModel, Field

from .. import audit, db, transfer_client
from ..auth.session import require, require_csrf

router = APIRouter(prefix="/api", tags=["transfer"])

MAX_UPLOAD = 5 * 1024 * 1024


@router.post("/transfer-files", status_code=201)
async def upload_transfer_file(request: Request, file: UploadFile = File(...),
                               principal: Principal = Depends(require(Role.COUNSELOR)),
                               _csrf: None = Depends(require_csrf)):
    """반출할 파일을 중계 transfer-staging 에 올린다. 검사 결과(scan_status, export_banned)는 중계가 정한다."""
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise GateError(ErrorCode.INVALID_REQUEST, "upload_too_large")
    name = "upload.json" if (file.content_type or "").endswith("json") else "upload.bin"
    resp = transfer_client.call(request, "POST", "/api/transfer-files",
                                files={"file": (name, data, file.content_type or "application/octet-stream")})
    (audit.allow(request, target_type="transfer_file") if resp.status_code == 201
     else audit.deny(request, f"transfer_status_{resp.status_code}"))
    return transfer_client.relay(resp)


class ExportRequestIn(BaseModel):
    file_id: uuid.UUID
    member_id: uuid.UUID
    recipient_id: uuid.UUID
    consent_id: uuid.UUID
    purpose: str = Field(min_length=1, max_length=64)
    expires_at: datetime


@router.post("/export-requests", status_code=201)
def create_export_request(body: ExportRequestIn, request: Request,
                          principal: Principal = Depends(require(Role.COUNSELOR)),
                          _csrf: None = Depends(require_csrf)):
    """반출 신청. 내부에서 먼저 '정보 주체가 내 담당 회원인지' 확인한 뒤 중계에 전달한다.
    검사 통과(passed) 파일만, 반출 기한·동의 확인은 중계가 다시 검사한다."""
    with db.connection() as conn:
        assigned = conn.execute("SELECT 1 FROM assignments WHERE user_id = %s AND member_id = %s",
                                (principal.user_id, body.member_id)).fetchone()
    if assigned is None:
        raise GateError(ErrorCode.ACCESS_DENIED, "member_not_assigned")
    resp = transfer_client.call(request, "POST", "/api/export-requests", json=body.model_dump(mode="json"))
    (audit.allow(request, target_type="export_request") if resp.status_code == 201
     else audit.deny(request, f"transfer_status_{resp.status_code}"))
    return transfer_client.relay(resp)


@router.get("/export-requests")
def list_export_requests(request: Request,
                         principal: Principal = Depends(require(Role.COUNSELOR, Role.APPROVER))):
    """counselor: 본인 신청만, approver: 전체 (중계가 토큰으로 구분). 화면용 가명 ID 를 덧붙인다."""
    resp = transfer_client.call(request, "GET", "/api/export-requests")
    if resp.status_code != 200:
        return transfer_client.relay(resp)
    body = resp.json()
    _with_pseudo_ids(body.get("items", []))
    return body


@router.get("/export-requests/{request_id}")
def get_export_request(request_id: uuid.UUID, request: Request,
                       principal: Principal = Depends(require(Role.COUNSELOR, Role.APPROVER))):
    resp = transfer_client.call(request, "GET", f"/api/export-requests/{request_id}")
    if resp.status_code != 200:
        return transfer_client.relay(resp)
    body = resp.json()
    _with_pseudo_ids([body])
    return body


def _with_pseudo_ids(items: list[dict]) -> None:
    """중계 응답의 user_id·member_id(UUID) 옆에 화면용 가명 ID 를 붙인다 (예: S-C01, M-001, M-B01).
    판단에는 쓰지 않는 표시 정보이며, 없는 값은 붙이지 않는다."""
    ids = {str(v) for it in items for k in ("requester_id", "recipient_id", "member_id") if (v := it.get(k))}
    if not ids:
        return
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT user_id::text AS id, pseudo_id FROM users WHERE user_id::text = ANY(%(ids)s)
               UNION ALL
               SELECT member_id::text, pseudo_id FROM members WHERE member_id::text = ANY(%(ids)s)""",
            {"ids": list(ids)}).fetchall()
    names = {r["id"]: r["pseudo_id"] for r in rows}
    for it in items:
        for k in ("requester_id", "recipient_id", "member_id"):
            if it.get(k) and str(it[k]) in names:
                it[k.replace("_id", "_pseudo_id")] = names[str(it[k])]


def _decide(request: Request, path: str, target: str):
    resp = transfer_client.call(request, "POST", path, json={})
    (audit.allow(request, target_type="export_request", target_id=target) if resp.status_code < 400
     else audit.deny(request, f"transfer_status_{resp.status_code}"))
    return transfer_client.relay(resp)


@router.post("/export-requests/{request_id}/approve")
def approve_export_request(request_id: uuid.UUID, request: Request,
                           principal: Principal = Depends(require(Role.APPROVER)),
                           _csrf: None = Depends(require_csrf)):
    """신청자 = 승인자면 중계가 거부. 회원 동의는 중계가 disclosure-checks 로 다시 확인."""
    return _decide(request, f"/api/export-requests/{request_id}/approve", str(request_id))


@router.post("/export-requests/{request_id}/reject")
def reject_export_request(request_id: uuid.UUID, request: Request,
                          principal: Principal = Depends(require(Role.APPROVER)),
                          _csrf: None = Depends(require_csrf)):
    return _decide(request, f"/api/export-requests/{request_id}/reject", str(request_id))


@router.post("/approvals/{approval_id}/revoke")
def revoke_approval(approval_id: uuid.UUID, request: Request,
                    principal: Principal = Depends(require(Role.APPROVER)),
                    _csrf: None = Depends(require_csrf)):
    return _decide(request, f"/api/approvals/{approval_id}/revoke", str(approval_id))
