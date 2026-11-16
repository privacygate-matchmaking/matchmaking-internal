"""회원 알림 (외부 회원 화면 오른쪽 위 종 아이콘). ※ 명세 외 추가

- 저장: 직원 알림과 같은 notifications 테이블 (user_id = 회원 Keycloak sub). 조회·읽음·삭제는 본인 것만.
- 만들기:
  · transfer-api 가 매칭·만남 일정·정보 공개 승인 사건을 POST /api/internal/member-notification-events 로 알린다
    (transfer-api 서비스 토큰만). 사건 종류(kind)만 받고 문구는 여기서 정한다 — 중계가 임의 문구를 넣을 수 없다.
  · 증빙·사진 심사 결과는 internal-api 가 심사 처리 중에 직접 만든다 (to_member).
- 문구에는 상대 이름·연락처·회원 코드를 넣지 않는다 (상대는 항상 "소개 상대").
- 알림 실패는 본 업무를 막지 않는다 (중계는 실패를 무시하고 감사 로그에만 남김).
"""
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Request
from privacygate.policy import Principal
from pydantic import BaseModel, ConfigDict, Field

from .. import audit, db
from ..auth.session import member_via_transfer, require_service

router = APIRouter(prefix="/api")

# kind → (제목, 본문, 외부 화면 탭)
EVENTS: dict[str, tuple[str, str, str]] = {
    "match_requested": ("새 매칭 신청", "소개 상대가 매칭을 신청했습니다. 매칭 현황에서 수락하거나 거절할 수 있습니다.", "matches"),
    "match_accepted": ("매칭 성사", "보낸 매칭 신청이 수락되었습니다. 매칭 현황에서 다음 단계를 확인하세요.", "matches"),
    "match_rejected": ("매칭 거절", "보낸 매칭 신청이 거절되었습니다.", "matches"),
    "match_cancelled": ("매칭 신청 취소", "받은 매칭 신청이 상대에 의해 취소되었습니다.", "matches"),
    "match_ended": ("매칭 종료", "소개 상대가 매칭을 종료했습니다. 공개 동의도 함께 종료되었습니다.", "matches"),
    "meeting_proposed": ("새 만남 일정 제안", "소개 상대가 만남 일정을 제안했습니다. 매칭 현황에서 후보를 확인하세요.", "matches"),
    "meeting_accepted": ("만남 일정 합의", "소개 상대가 일정에 동의했습니다. 담당 직원 승인 후 확정됩니다.", "matches"),
    "meeting_change_requested": ("다른 일정 요청", "소개 상대가 다른 일정을 요청했습니다. 새 일정을 제안해 주세요.", "matches"),
    "meeting_confirmed": ("만남 일정 확정", "담당 직원이 만남 일정을 승인해 확정했습니다.", "matches"),
    "meeting_cancelled": ("만남 일정 반려·취소", "만남 일정이 반려되었거나 확정이 취소되었습니다. 새 일정을 다시 제안할 수 있습니다.", "matches"),
    "release_approved": ("상대 정보 공개", "승인된 소개 상대의 정보가 도착했습니다. 매칭 현황 또는 제공 자료에서 확인하세요.", "matches"),
    "release_revoked": ("정보 공개 회수", "받은 소개 상대의 정보 제공이 회수되었습니다. 더 이상 열람·다운로드할 수 없습니다.", "deliveries"),
}
EventKind = Literal[tuple(EVENTS)]  # type: ignore[valid-type]

EVIDENCE_KO = {"education": "졸업증명서(학력)", "employment": "재직증명서", "identity": "신분증(본인 확인)",
               "marital": "혼인관계증명서", "income": "소득 증빙", "property": "부동산 증빙", "photo": "프로필 사진"}


def _insert(conn, user_id, kind: str, title: str, body: str, view: str | None) -> int:
    """활성 회원 계정에만 만든다 (직원 계정·없는 계정에는 만들지 않음)."""
    return conn.execute(
        """INSERT INTO notifications (user_id, kind, title, body, link_view)
           SELECT u.user_id, %s, %s, %s, %s FROM users u
            WHERE u.user_id = %s::uuid AND u.role = 'member' AND u.active""",
        (kind, title, body, view, str(user_id))).rowcount


def to_member(conn, member_id, kind: str, title: str, body: str, view: str | None) -> None:
    """업무 회원(member_id)에게 알림. 로그인 계정이 없는 회원(시드 등)은 건너뛴다."""
    row = conn.execute("SELECT user_id FROM members WHERE member_id = %s", (str(member_id),)).fetchone()
    if row and row["user_id"]:
        _insert(conn, row["user_id"], f"member_{kind}", title, body, view)


def evidence_reviewed(conn, member_id, evidence_kind: str, result: str) -> None:
    label = EVIDENCE_KO.get(evidence_kind, "증빙")
    view = "account" if evidence_kind == "photo" else "evidence"
    if result == "passed":
        to_member(conn, member_id, "evidence_passed", "심사 통과", f"{label} 심사가 통과되었습니다.", view)
    else:
        to_member(conn, member_id, "evidence_rejected", "심사 반려",
                  f"{label}이(가) 반려되었습니다. 내용을 확인하고 다시 제출해 주세요.", view)


class MemberEventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_ids: list[uuid.UUID] = Field(min_length=1, max_length=2)
    kind: EventKind


@router.post("/internal/member-notification-events")
def member_notification_event(body: MemberEventIn, request: Request,
                              _svc: dict = Depends(require_service("transfer-api"))):
    title, text, view = EVENTS[body.kind]
    created = 0
    with db.connection() as conn:
        for user_id in dict.fromkeys(body.user_ids):
            created += _insert(conn, user_id, f"member_{body.kind}", title, text, view)
    audit.allow(request, action="member.notify", target_type="member_notification", reason=f"{body.kind}:{created}")
    return {"created": created}


def _iso(value):
    return value.isoformat() if value is not None else None


def _unread(conn, user_id) -> int:
    return conn.execute("SELECT count(*) AS n FROM notifications WHERE user_id = %s AND read_at IS NULL",
                        (user_id,)).fetchone()["n"]


@router.get("/internal/my-notifications")
def my_notifications(request: Request, member: Principal = Depends(member_via_transfer)):
    with db.connection() as conn:
        rows = conn.execute("""SELECT notification_id, kind, title, body, link_view, created_at, read_at
                                 FROM notifications WHERE user_id = %s ORDER BY created_at DESC LIMIT 100""",
                            (member.user_id,)).fetchall()
        unread = _unread(conn, member.user_id)
    return {"unread": unread,
            "items": [{"notification_id": str(r["notification_id"]), "kind": r["kind"], "title": r["title"],
                       "body": r["body"], "link_view": r["link_view"], "created_at": _iso(r["created_at"]),
                       "read": r["read_at"] is not None} for r in rows]}


class MySelect(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[uuid.UUID] = Field(default_factory=list, max_length=200)
    all: bool = False


@router.post("/internal/my-notifications/read")
def read_my_notifications(body: MySelect, request: Request, member: Principal = Depends(member_via_transfer)):
    with db.connection() as conn:
        if body.all:
            n = conn.execute("UPDATE notifications SET read_at = now() WHERE user_id = %s AND read_at IS NULL",
                             (member.user_id,)).rowcount
        else:
            n = conn.execute("""UPDATE notifications SET read_at = now()
                                 WHERE user_id = %s AND read_at IS NULL AND notification_id = ANY(%s::uuid[])""",
                             (member.user_id, [str(i) for i in body.ids])).rowcount
        unread = _unread(conn, member.user_id)
    return {"updated": n, "unread": unread}


@router.post("/internal/my-notifications/delete")
def delete_my_notifications(body: MySelect, request: Request, member: Principal = Depends(member_via_transfer)):
    with db.connection() as conn:
        if body.all:
            n = conn.execute("DELETE FROM notifications WHERE user_id = %s", (member.user_id,)).rowcount
        else:
            n = conn.execute("DELETE FROM notifications WHERE user_id = %s AND notification_id = ANY(%s::uuid[])",
                             (member.user_id, [str(i) for i in body.ids])).rowcount
        unread = _unread(conn, member.user_id)
    return {"deleted": n, "unread": unread}
