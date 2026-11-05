"""반출(중계) 화면용 API. 브라우저 → internal-api → transfer-api.

브라우저는 transfer-api 주소도 서비스 인증정보도 모른다. internal-api 가 1차로 역할을 확인하고,
서버에 보관한 사용자 access token(aud=transfer-api, Keycloak 서명)을 붙여 transfer-api 로 전달한다.
transfer-api 는 그 토큰으로 신청자·승인자를 직접 확인하고 다시 검사한다 (이중 확인).
전달 구현은 3주차. 지금은 경로와 허용 역할만 확정한다.
"""
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from privacygate.policy import Principal, Role

from ..auth.session import require, require_csrf

router = APIRouter(prefix="/api", tags=["transfer"])


def _todo() -> JSONResponse:
    return JSONResponse({"status": "not_implemented", "detail": "3주차 구현 예정"}, status_code=501)


@router.post("/transfer-files")
def upload_transfer_file(principal: Principal = Depends(require(Role.COUNSELOR)),
                         _csrf: None = Depends(require_csrf)):
    """반출할 파일을 transfer-staging 에 올리고 검사 (scan_status: pending → passed/blocked/error)."""
    return _todo()


@router.post("/export-requests")
def create_export_request(principal: Principal = Depends(require(Role.COUNSELOR)),
                          _csrf: None = Depends(require_csrf)):
    """검사 통과(passed) 파일만 신청 가능. 검사 통과는 승인이 아니다."""
    return _todo()


@router.get("/export-requests")
def list_export_requests(principal: Principal = Depends(require(Role.COUNSELOR, Role.APPROVER))):
    """counselor: 본인 신청만, approver: 검토 대기 건."""
    return _todo()


@router.get("/export-requests/{request_id}")
def get_export_request(request_id: str,
                       principal: Principal = Depends(require(Role.COUNSELOR, Role.APPROVER))):
    return _todo()


@router.post("/export-requests/{request_id}/approve")
def approve_export_request(request_id: str, principal: Principal = Depends(require(Role.APPROVER)),
                           _csrf: None = Depends(require_csrf)):
    """신청자 = 승인자면 transfer-api 가 거부. 회원 동의는 disclosure-checks 로 따로 확인."""
    return _todo()


@router.post("/export-requests/{request_id}/reject")
def reject_export_request(request_id: str, principal: Principal = Depends(require(Role.APPROVER)),
                          _csrf: None = Depends(require_csrf)):
    return _todo()


@router.post("/approvals/{approval_id}/revoke")
def revoke_approval(approval_id: str, principal: Principal = Depends(require(Role.APPROVER)),
                    _csrf: None = Depends(require_csrf)):
    return _todo()
