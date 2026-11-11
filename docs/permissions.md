# 권한 표 (PrivacyGate)

| 역할 | 시험 계정 | 할 수 있는 일 | 자동으로 주지 않는 권한 |
|---|---|---|---|
| counselor | `counselor_a` (내부 공격자 A), `counselor_b` | 담당 회원 조회·정보 수정·탈퇴 처리, 담당 회원 증빙 열람·심사, 반출 파일 업로드·신청(본인이 만든 내보내기 결과 등록 포함), 본인 신청 조회 | 전체 회원 내보내기, 증빙 제출·열람, 승인 |
| data_admin (총관리자) | `super_admin`, `data_admin` | 전체 회원 조회·정보 수정·탈퇴 처리, 전체 증빙 열람·심사, 전체 회원 내보내기·내역, 배정된 증빙 목록·열람·심사 | **반출 승인** |
| approver | `approver` | 반출 신청 검토·승인·거절·회수 | **전체 내보내기, 원본 증빙 열람** |
| member | `member_b` (외부 공범 B) | 본인 증빙 제출·심사 상태 확인, 본인 동의 등록·철회, 나에게 온 전달 목록·다운로드 (외부 화면만) | 내부 화면 로그인, 증빙 원본 열람, 다른 회원 명의 동의 |
| (Keycloak 운영) | `infra_admin` | Keycloak 관리 콘솔 | 업무 데이터 접근 |

규칙
- 신원·역할은 서버 인증 정보(세션, Keycloak 서명 토큰)와 `matchmaking_business.users` 에서 확인한다. 요청 본문의 user_id 는 믿지 않는다.
- internal-api 는 역할을 매 요청 DB 에서 다시 읽는다 (비활성화·역할 변경 즉시 반영).
- transfer-api 는 업무 DB 가 없으므로 Keycloak 서명 토큰의 realm 역할로 확인한다. Keycloak 역할과 `users.role` 은 같게 관리한다.
- 신청자 = 승인자이면 서버가 거부한다 (`privacygate.policy.can_decide_request`).
- `GATE_MODE=baseline`(시연 비교용)에서는 관리자 내보내기의 역할 검사와 다운로드의 "요청 file_id ↔ 승인 파일" 연결 검사만 꺼진다. 기본값은 `enforce`.
- 회원은 소개된 상대(`introductions`)에게만 동의를 등록할 수 있다.
- 회원 간 매칭: 소개된 두 회원이 서로 매칭을 누르면 양쪽 프로필 제공 동의(30일)가 만들어진다. 매칭 취소·탈퇴 시 철회.
- 새 회원은 활성 상담 직원 중 한 명에게 무작위로 배정된다 (DB 트리거). 상담 직원은 배정된 회원만, 총관리자는 전체 회원을 본다 (이름·연락처는 둘 다 화면에 없음).
- 직원 승인과 회원 동의는 각각 확인한다. 반출 금지 자료는 승인으로도 허용되지 않는다.
- 권한 선언이 없는 `/api` 경로가 있으면 서버가 시작하지 않는다 (`assert_all_routes_guarded`).
- 서버 간 호출(`/api/internal/*`)은 Keycloak 서비스 토큰의 `azp` 로 호출자를 확인한다.
  - internal-api `/api/internal/disclosure-checks` ← `transfer-api`
  - internal-api `/api/evidence-files` ← `transfer-api` (+ 회원 access token, 회원 증빙 제출)
  - transfer-api `/api/internal/*` ← `external-api` (+ 회원 access token)

인증
- 직원: ID·비밀번호 + TOTP (첫 로그인에 OTP 등록 강제), 회원: ID·비밀번호
  - 개발 중에만 `.env` 의 `REQUIRE_STAFF_OTP=false` 로 끌 수 있다. 기본값과 시연·평가는 `true`.
- 5회 실패 시 잠금(점증 대기), 비밀번호 12자 이상
- 세션: 유휴 30분, 최대 8시간, 로그인마다 새 세션 ID, 로그아웃 시 서버 세션·Keycloak 세션 종료
- 브라우저 구간은 HTTPS 만 (internal-web·external-web·Keycloak 8443), 세션 쿠키 Secure·HttpOnly·SameSite=Strict
