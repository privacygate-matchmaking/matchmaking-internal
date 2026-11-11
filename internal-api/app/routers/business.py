"""내부 업무 API (docs/api-spec.md 의 '내부' 구현 위치).

이번 주는 경로·허용 역할·CSRF 만 확정한다. 권한 검사는 자료를 읽거나 파일을 만들기 전에 끝난다.
기능 구현은 일정표 2~3주차. 구현 전에는 501 을 돌려준다.
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from privacygate import gate_mode
from privacygate.policy import STAFF_ROLES, Principal, Role

from .. import audit
from ..auth.session import member_via_transfer, require, require_csrf, require_service

router = APIRouter(prefix="/api", tags=["business"])


def _todo(week: str) -> JSONResponse:
    return JSONResponse({"status": "not_implemented", "detail": f"{week} 구현 예정"}, status_code=501)


@router.get("/me")
def me(request: Request, principal: Principal = Depends(require(*STAFF_ROLES))):
    """화면 표시용. 역할은 서버가 매 요청 확인하므로 화면은 이 값을 표시에만 쓴다."""
    return {"user_id": principal.user_id, "pseudo_id": principal.pseudo_id, "role": principal.role,
            "csrf_token": request.state.csrf_token,
            "gate_mode": gate_mode.current()}      # baseline 이면 화면 상단에 경고 표시


# ---------- 회원 ----------
@router.get("/members")
def list_members(principal: Principal = Depends(require(Role.COUNSELOR))):
    """담당 관계가 있는 회원의 허용 항목만 (2주차)."""
    return _todo("2주차")


@router.get("/members/{member_id}")
def get_member(member_id: str, principal: Principal = Depends(require(Role.COUNSELOR))):
    """담당 회원 상세, 담당이 아니면 404 (존재를 공개하지 않음) (2주차)."""
    return _todo("2주차")


# ---------- 관리자 전체 회원 내보내기 (공격 ① 대상) ----------
@router.post("/admin/member-exports")
def create_member_export(request: Request,
                         principal: Principal = Depends(require(Role.DATA_ADMIN, baseline_open=True)),
                         _csrf: None = Depends(require_csrf)):
    """전체 회원 내보내기. 결과 파일은 서버 내부 저장소에만 두고 export_id 와 건수만 응답한다
    (브라우저로 내려받는 경로는 두지 않음).
    GATE_MODE=baseline 이면 역할 검사를 건너뛴다 (공격 ① 비교 시연용)."""
    audit.allow(request, target_type="member_export")
    return _todo("3주차")


@router.post("/member-exports/{export_id}/transfer-files")
def register_export_to_transfer(export_id: str, request: Request,
                                principal: Principal = Depends(require(Role.COUNSELOR)),
                                _csrf: None = Depends(require_csrf)):
    """내보내기 결과를 중계 반출 대기 영역에 등록한다 (공격 연결 단계). ※ 명세 외 추가
    - 본인이 만든 내보내기(member_exports.created_by)만 등록할 수 있다. enforce 에서는 counselor 가
      내보내기를 만들 수 없으므로 등록할 대상이 없다.
    - internal-api 가 evidence-storage/exports/ 의 파일을 복호화해 바이트를 multipart 로
      transfer-api POST /api/transfer-files 에 보낸다 (직원 토큰 첨부). 파일 경로·볼륨은 공유하지 않는다.
    - 중계 응답의 file_id 를 member_exports.transfer_file_id 에 저장. CSV 는 중계에서 blocked/export_banned 로 등록된다 (3주차)."""
    return _todo("3주차")


# ---------- 증빙 ----------
@router.post("/evidence-files")
def submit_evidence(member: Principal = Depends(member_via_transfer)):
    """회원 증빙 제출 (회원 → external-api → transfer-api → 여기).
    본인(member_id = 토큰 sub 의 회원)만, 형식·크기 검사 → AES-GCM 암호화 → evidence-storage 저장 (2주차).
    직원 계정은 제출할 수 없다."""
    return _todo("2주차")


@router.get("/evidence-files")
def list_evidence(principal: Principal = Depends(require(Role.DATA_ADMIN))):
    """나에게 배정된 증빙 목록만 (file_id, 회원 가명 ID, 접수일, 상태, 삭제 기한). 원본 내용은 넣지 않는다.
    ※ 명세 외 추가: 심사자가 열람할 file_id 를 알기 위해 필요 (2주차)."""
    return _todo("2주차")


@router.get("/evidence-files/{file_id}/content")
def read_evidence(file_id: str, principal: Principal = Depends(require(Role.DATA_ADMIN))):
    """배정된 데이터 관리자만, 심사 중에만 복호화 열람 (2주차)."""
    return _todo("2주차")


@router.post("/evidence-files/{file_id}/review")
def review_evidence(file_id: str, principal: Principal = Depends(require(Role.DATA_ADMIN)),
                    _csrf: None = Depends(require_csrf)):
    """심사 결과 저장, 원본 삭제 기한 설정 (2주차)."""
    return _todo("2주차")


# ---------- 서버 간: 중계가 관계·동의를 확인 ----------
@router.post("/internal/disclosure-checks")
def disclosure_check(claims: dict = Depends(require_service("transfer-api"))):
    """transfer-api 서비스 토큰만 허용. 수신자-대상 회원 관계·동의 유효성만 답한다 (3주차)."""
    return _todo("3주차")


# ---------- 회원 본인 기능 (회원 → external-api → transfer-api → 여기) ※ 명세 외 추가 ----------
# 모두 transfer-api 서비스 토큰 + 회원 access token 을 검증하고, 회원 토큰 sub 의 회원 본인 자료만 다룬다.

@router.get("/internal/my-evidence-files")
def my_evidence_files(member: Principal = Depends(member_via_transfer)):
    """내가 제출한 증빙의 심사 상태만 (file_id, 접수일, 상태, 심사 결과). 원본 내용·심사자 정보는 주지 않는다 (2주차)."""
    return _todo("2주차")


@router.get("/internal/my-consents")
def my_consents(member: Principal = Depends(member_via_transfer)):
    """내 동의 목록 (consent_id, 상대 회원 가명 ID, 항목, 목적, 만료, 철회 여부) (3주차)."""
    return _todo("3주차")


@router.post("/internal/my-consents")
def create_consent(member: Principal = Depends(member_via_transfer)):
    """동의 등록: 상대 회원·항목(profile/photo/contact)·목적·만료일. 본인 명의로만 (3주차)."""
    return _todo("3주차")


@router.post("/internal/my-consents/{consent_id}/revoke")
def revoke_consent(consent_id: str, member: Principal = Depends(member_via_transfer)):
    """동의 철회: revoked_at 기록. 이후 이 동의에 기댄 전달은 CONSENT_INVALID 로 막힌다 (3주차)."""
    return _todo("3주차")
