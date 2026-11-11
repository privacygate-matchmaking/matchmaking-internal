# 회원 매칭 기능 — 외부(external-web·external-api·transfer-api) 연동 요청

내부(internal-api)에 회원 간 매칭이 추가되었습니다. 회원 화면의 "제공 동의 등록" 대신 **매칭 버튼**으로 동의를 만듭니다.
기존 동의 API(`/api/internal/my-consents`)와 반출 신청·승인·다운로드 흐름은 **바뀌지 않습니다** (동의를 만드는 방법만 추가).

## 동작
- 회원은 소개된 상대(`introductions`)에게만 매칭을 누를 수 있습니다.
- 두 회원이 **서로** 누르면 매칭 성사 → 양쪽에 프로필 제공 동의가 자동 생성됩니다 (item=`profile`, purpose=`introduction`, 30일).
- 매칭 취소 시 매칭으로 만든 양쪽 동의가 철회됩니다. 탈퇴 회원은 상대 목록에서 빠집니다.
- 시드: 회원 1(M-001, 로그인 계정 없음)은 이미 member_b(M-003)에게 매칭을 눌러 둔 상태 → member_b 가 M-001 에게 매칭을 누르면 성사.

## internal-api (transfer-api 서비스 토큰 + `X-User-Token` 회원 토큰, 기존 my-consents 와 같은 방식)

| 메서드 | 경로 | 요청 → 응답 |
|---|---|---|
| GET | `/api/internal/my-matches` | → `{"items": [{counterpart_member_id, counterpart_pseudo_id, i_matched, they_matched, matched, matched_at}]}` |
| POST | `/api/internal/my-matches` | `{"counterpart_member_id": "<uuid>"}` → 201 `{counterpart_member_id, matched}` (소개되지 않은 상대 403) |
| POST | `/api/internal/my-matches/{counterpart_member_id}/cancel` | `{}` → `{counterpart_member_id, cancelled: true, revoked_consents}` (매칭 없음 404) |

## 외부에서 추가할 것 (제안)
- transfer-api: `/api/internal/member-matches` (GET·POST), `/api/internal/member-matches/{id}/cancel` → 위 internal-api 경로로 전달 (my-consents 전달과 동일 패턴)
- external-api: `/api/me/matches` (GET·POST), `/api/me/matches/{id}/cancel`
- external-web: "제공 동의" 탭을 "매칭" 탭으로 — 상대별 [매칭하기] / [매칭 취소] 버튼, 상태 표시(내가 누름·상대가 누름·성사)

## 함께 부탁드리는 것
1. `services/ieum/identity.py` JWKS 로딩: `use == "sig"` 인 키만 읽도록 (Keycloak 의 RSA-OAEP 암호화 키 때문에 모든 토큰이 거부되던 문제. 현재는 Keycloak 에서 암호화 키를 꺼서 우회 중)
2. `GET /api/export-requests` 목록 항목에 `approval_id` 포함 (승인 후 회수 버튼용)
