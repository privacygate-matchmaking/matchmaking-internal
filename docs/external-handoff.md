# 내부 변경 정리 — 외부(external-web·external-api·transfer-api)·Wazuh 담당 전달용

이번 주 내부(internal-api·privacygate)에서 바뀐 것 중 **외부 쪽에 영향이 있는 것만** 정리했습니다.
반출 신청·승인·다운로드 흐름과 기존 API 형식은 그대로입니다. 아래 "외부에서 할 일"만 반영해 주시면 됩니다.

## 0. 먼저 할 일 (실행 환경)

1. `.env` 에 두 줄 추가 (없으면 compose 가 시작되지 않음). 값은 각자 무작위로:
   ```bash
   echo "INTERNAL_ADMIN_CLIENT_SECRET=$(openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-32)" >> .env
   echo "MEMBER_NOTICE_DAYS=30" >> .env
   ```
2. 시험 데이터가 전부 바뀌었으므로 초기화 후 재기동: `docker compose ... down -v` → `up -d --build`
   (`down -v` 는 업무 DB·중계 DB·Keycloak·증빙 저장소를 모두 지웁니다)

## 1. 계정·로그인 (Keycloak)

- **OTP 제거**: 직원·회원 모두 ID·비밀번호 로그인.
- 직원 계정: `counselor_a`, `counselor_b`(추가), `data_admin`(= 총관리자), `approver`. `super_admin` 은 없음.
- 회원 계정: `member_b` = 회원 **A-003 박도윤**. 비밀번호는 모두 `.env` 의 `KC_TEST_PASSWORD`.
- Keycloak 의 토큰 암호화 키(RSA-OAEP, use=enc)를 껐습니다 → 중계가 직원 토큰을 `invalid_token` 으로 거부하던 문제 해결.
  - 부탁: `services/ieum/identity.py` JWKS 로딩에서 `use == "sig"` 키만 읽도록 바꿔 주세요 (키 설정이 바뀌어도 안전하게).
- 새 client `internal-admin`: internal-api 가 탈퇴 회원 Keycloak 계정을 정리할 때만 씀 (외부에서 쓸 일 없음).

## 2. 코드 규칙·표시

- 직원 `A-C01`(상담)·`A-D01`(총관리자)·`A-P01`(승인), 회원 `A-001`~`A-999` → `B-001` (자동 발급).
- **회원 코드는 관리자 전용** → 회원에게 가는 응답에서 뺐습니다. 상대 표시는 `counterpart_label`
  (예: "소개 상대 · 만 32세 · 4년제 대졸")을 써 주세요.
  - `my-consents` 의 `counterpart_pseudo_id` → `counterpart_label` 로 바뀜.

## 3. 시험 데이터 (시드)

- 회원 20명 (A-001~A-020). counselor_a 담당 A-001~A-010, counselor_b 담당 A-011~A-020.
- member_b(A-003) 소개 상대: A-001, A-002, A-004. A-001 은 이미 A-003 에게 매칭을 눌러 둠.
- member_b 는 학력 증빙이 없음 → 졸업증명서 제출 → 직원 통과 → A-001 에게 매칭하면 바로 성사.

## 4. 회원 매칭 (새 기능)

회원 화면의 "제공 동의 등록" 대신 **매칭 버튼**으로 동의가 만들어집니다.
- 소개된 상대에게만 매칭 가능. **학력 증빙이 통과되어야** 매칭 가능 (`can_match=false` → "학력 증빙 승인 후 매칭할 수 있습니다").
- 두 회원이 서로 누르면 성사 → 양쪽 프로필 제공 동의 자동 생성 (item=`profile`, purpose=`introduction`, 30일). 취소하면 양쪽 동의 철회.
- 매칭 전 공개 카드(`card`): 만 나이·키·몸무게·학력 구분·소개 (실명·학교·직장·연락처 없음).

## 5. 증빙 종류

- 증빙 제출 multipart 에 `kind` = `education`(졸업증명서) / `employment`(재직증명서). 생략 시 education.
- **부탁**: transfer-api `evidence_submit` 이 지금 `kind` 를 넘기지 않습니다. form 필드 `kind` 를 받아 internal-api 로 같이 전달해 주세요.
  회원 화면 증빙 제출에도 종류 선택을 넣어 주세요.

## 6. 소개 자료 (매칭·승인 후 받는 파일)

직원이 파일을 올리지 않고 서버가 회원 DB 로 만듭니다. 형식은 지금 중계 검사(`PROFILE_FIELDS`, 4개 항목·각 300자) 그대로:
- `member_pseudo_id` = **실명** (회원 코드 아님), `age_band` = "만 32세"
- `job_group` = 직군 (+ 재직 증빙 통과 시 " · 회사명 (재직 증빙 확인)")
- `introduction` = "키 …cm · 몸무게 …kg (본인 신고) / 학력 … (학교 전공) · 학력 증빙 확인 / 소개 …"
- 화면용 이름은 `A-001_file1` 형식 (직원 화면 전용).

## 7. 회원 탈퇴·탈퇴 안내 (새 기능)

- 탈퇴 경로: 직원·총관리자 처리, 또는 **회원 본인 신청** → 7일 유예 → 회원 정보 삭제.
  - 유예 중에는 회원 기능(매칭·동의·증빙 조회)이 403. 본인 신청 건만 회원이 철회 가능, 직원 처리 건은 철회 불가.
- 삭제되면 그 회원의 Keycloak 세션을 바로 끊습니다 → 외부 화면에서 토큰 갱신이 실패하면 로그인 화면으로 보내 주세요.
- 삭제 후 `MEMBER_NOTICE_DAYS`(기본 30일) 동안은 로그인은 되지만 안내만 보입니다. 기간이 지나면 Keycloak 계정도 삭제(로그인 불가).
- **외부 화면: 회원 로그인 직후 `my-status` 를 먼저 불러, `status != "active"` 이면 `message` 를 그대로 보여 주세요.**
  - 직원이 처리: "관리자에 의해 탈퇴 처리된 계정입니다. 사유: …" / 유예 중이면 "… 처리 중인 계정입니다 (YYYY-MM-DD 삭제 예정). 사유: …"
  - 본인이 탈퇴: "탈퇴된 계정입니다." / 유예 중이면 "탈퇴 신청한 계정입니다 (…). 그 전까지 탈퇴를 철회할 수 있습니다." + [탈퇴 철회] 버튼(`can_cancel=true`)
  - `withdrawn` 이면 안내 후 로그아웃.

## 8. 새 internal-api 경로 (transfer-api 서비스 토큰 + `X-User-Token`, 기존 my-consents 와 같은 방식)

| 메서드 | 경로 | 요청 → 응답 |
|---|---|---|
| GET | `/api/internal/my-matches` | → `{can_match, items: [{counterpart_member_id, counterpart_label, card, i_matched, they_matched, matched, matched_at}]}` |
| POST | `/api/internal/my-matches` | `{counterpart_member_id}` → 201 `{counterpart_member_id, matched}` (소개 안 된 상대 403, 학력 미통과 409 `education_not_verified`) |
| POST | `/api/internal/my-matches/{counterpart_member_id}/cancel` | `{}` → `{counterpart_member_id, cancelled, revoked_consents}` |
| GET | `/api/internal/my-status` | → `{status: active\|withdraw_pending\|withdrawn\|not_registered, by?: self\|staff, reason?, withdraw_at?, withdrawn_at?, can_cancel?, message}` (회원 정보가 지워진 뒤에도 토큰만 유효하면 응답) |
| POST | `/api/internal/my-withdrawal` | `{reason?: ≤200자}` → `{status: "withdraw_pending", withdraw_at}` (이미 유예 중 409) |
| POST | `/api/internal/my-withdrawal/cancel` | `{}` → `{status: "active"}` (유예 아님 409, 직원 처리 건 403 `withdraw_requested_by_staff`) |

외부에 추가할 경로 (제안, 기존 member-consents 전달과 같은 패턴):
- transfer-api: `/api/internal/member-matches` (GET·POST), `/api/internal/member-matches/{id}/cancel`, `/api/internal/member-status` (GET), `/api/internal/member-withdrawal` (POST), `/api/internal/member-withdrawal/cancel` (POST)
- external-api: `/api/me/matches` (GET·POST), `/api/me/matches/{id}/cancel`, `/api/me/status` (GET), `/api/me/withdrawal` (POST), `/api/me/withdrawal/cancel` (POST)
- external-web: "제공 동의" 탭 → "매칭" 탭 (상대별 [매칭하기]/[매칭 취소], 상태 표시), 내 정보에 [회원 탈퇴] (확인 팝업 + 사유 선택 입력)
- 참고: transfer-api `upstream()` 의 허용 오류 코드 목록에 이미 `INVALID_STATE`·`ACCESS_DENIED` 가 있어 409·403 이 그대로 전달됩니다.

## 9. Wazuh 참고 (internal-api 감사 로그 `/var/log/matchmaking/internal-api.json`)

한 줄 한 건 JSON (`trace_id, actor, role, action, target_type, target_id, result, reason`). 이번에 추가·의미 있는 항목:

| 조건 | 의미 | 경보 제안 |
|---|---|---|
| `action=member_purge`, `result=error` | 탈퇴 회원 삭제 실패 | 높음 |
| `action=evidence_delete`, `result=error` | 증빙 원본 파일 삭제 실패 | 높음 |
| `action=member_account_delete`, `result=error` (`reason=not_member_account`) | 탈퇴 계정 정리 중 **직원 계정 삭제 시도가 거부됨** | 높음 |
| `action=member_account_delete`, `result=allow` | 탈퇴 회원 Keycloak 계정 삭제 | 기록 |
| `target_type=member_purged` (`role=data_admin`) | 총관리자 즉시 탈퇴 | 기록 |
| `target_type=member_withdraw_scheduled` / `member_withdraw_self` | 직원 처리 / 회원 본인 탈퇴 신청 | 기록 (짧은 시간 다수면 중간) |
| `target_type=member_list_all`, `role=data_admin` | 전체 회원 조회 | 기록 |
| `action=POST /api/admin/member-exports`, `result=deny` | 총관리자가 아닌 직원의 전체 내보내기 시도 (공격 ①) | 높음 |
| `result=deny`, `reason=member_not_in_scope` | 담당이 아닌 회원 접근 시도 (404 로 응답) | 반복되면 중간 |

## 10. 내부 권한 자동 시험 (참고)

`matchmaking-internal/tests/test_permissions.py` — 담당 범위 404, 즉시 탈퇴 총관리자 전용, 알림 본인 한정,
회원 기능 서비스 토큰 필수, 직원 처리 탈퇴 회원 철회 불가, Keycloak 정리는 member 계정만 (15건).
실행: privacygate 폴더에서 `docker compose exec -T internal-api python - < ../matchmaking-internal/tests/test_permissions.py`
