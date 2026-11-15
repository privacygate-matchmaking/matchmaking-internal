# 내부 변경 정리 — 외부(external-web·external-api·transfer-api)·Wazuh 담당 전달용

> 2026-11-14 후속: 아래는 변경 전 전달 원문입니다. 매칭 4·8절과 소개 파일 6절은 [유료 매칭·UUID 연결](paid-matching-integration.md)의 새 코드 계약으로 대체됩니다. 기존 DB 초기화는 자동 수행하지 않았습니다.

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

## 11. 증빙 확장·자동 검사·연락처 전달 (11월 15일 추가)

이번에는 사용자 결정으로 **외부 레포 코드도 함께 수정**했습니다. 기존 흐름(신청 → 수락 → 공개 동의 → 직원 발송 요청 → 승인 → 다운로드)과 API 형식은 유지하고 범위만 넓혔습니다.

### 무엇이 바뀌었나
- 증빙 종류 추가: `identity`(신분증), `marital`(혼인관계증명서), `income`(소득), `property`(부동산)는 PDF, `photo`(프로필 사진)는 JPEG·PNG.
- 내부에 **doc-inspector** 컨테이너 추가 (로컬 Tesseract OCR + 규칙 탐지). 개인정보를 찾아 가리고, 발급번호를 합성 발급대장과 대조해 진위를 판단합니다. 외부로 문서를 보내지 않습니다.
- 공개 범위(scope) 추가: `property`, `documents`. 기존 `photo`·`contact`·`income`·`marital_status`도 실제로 동작합니다.
  - 화면 열람(동의만): profile·education·employment·income·marital_status·property 의 **검토 결과 텍스트**.
  - 승인 자료 전용(동의 + 담당 직원 요청 + 승인자 승인): `photo`(검토 사진), `documents`(함께 선택한 서류의 마스킹 사본), `contact`(연락처).
- 연락처 조건: 두 회원 모두 `contact` 동의 + 만남 일정 확정(`matching_meeting_proposals.status='confirmed'`) + 자료 주인 신분증 통과. 요청·승인·다운로드 때마다 다시 확인하고, 한쪽이 철회하면 재다운로드가 막힙니다.

### 외부 레포에서 바꾼 파일
| 파일 | 내용 |
|---|---|
| `services/ieum/matching.py` | `Scope` 에 property·documents 추가, Sharing 최대 9개 |
| `services/ieum/matching_routes.py` | `Attachment` 모델(형식·base64·SHA-256·파일 머리 검사), `ResultField.attachments`, 화면 열람에서 승인 전용 범위 제외 + `release_only_scopes` 응답 |
| `services/ieum/matching_release.py` | 반출 가능 범위 확장, `contact_ready()`(상호 동의·일정 확정) 확인을 요청·승인·다운로드에 추가, 직원 현황에 `contact_ready` |
| `services/ieum/transfer.py`, `external.py` | 증빙 종류 7가지, 사진은 JPEG/PNG·서류는 PDF 머리 검사 |
| `external-web/public/material.js` (새 파일) | "제공 자료 → 자료 보기": 검토 텍스트·사진·마스킹 사본·연락처를 화면에 표시 (이미지 형식·문자 검사 후 data: 주소) |
| `external-web/public/matching.js`, `app.js`, `index.html`, `style.css` | 공개 동의 항목 전체 표시(승인 전용 표시·안내), 증빙 종류 선택 확장, 자료 보기 버튼 |
| `tests/integration/*`, `tests/frontend/material.test.cjs`, `.github/workflows/tests.yml` | 연락처 조건·첨부 검증·증빙 형식 시험 추가 (통합 133건, 프런트 15건 통과) |

### 반출 자료 형식 (schema_version 3 유지)
`fields[]` 항목에 선택적으로 `attachments: [{name, label, media_type: image/png|image/jpeg, sha256, data_base64}]` 가 붙습니다. 중계는 승인·다운로드 때 내부 결과를 다시 받아 **첨부까지 그대로 같은지** 비교합니다(사본 바꿔치기 차단).

### Wazuh 참고 (추가 감사 항목)
| 조건 | 의미 |
|---|---|
| `action=evidence_inspect`, `result=error` | 자동 검사 실패 (doc-inspector 장애·읽을 수 없는 파일) |
| `action=evidence_inspect`, `reason=suspicious` | 진위 의심 서류 제출 (발급번호 위조·명의 불일치) → 중간 경보 제안 |
| `target_type=evidence_inspection` / `evidence_masked` | 직원의 검사 결과·마스킹 사본 열람 |
| 중계 `CONSENT_INVALID` + 연락처 메시지 | 조건 미충족 연락처 반출 시도 |

### 시험 데이터
`./infra/scripts/make-sample-evidence.sh A-003` 로 회원 A-003 의 합성 서류 6종 + 사진을 만들 수 있습니다 (발급번호가 합성 발급대장과 맞아 "진위 확인"이 나옵니다).

### 내 계정 (11월 15일 추가)
- "내 계정" 탭을 항상 표시하고 구성을 바꿨습니다: ① 로그인 비밀번호 변경 ② 프로필 사진 등록·변경 ③ 키·몸무게 ④ 연락처 변경 ⑤ 회원 탈퇴(회원 상태 연동이 켜진 경우만).
- 비밀번호: `/auth/login?action=password` → Keycloak 비밀번호 변경 화면(`kc_action=UPDATE_PASSWORD`) → 일반 로그인처럼 돌아옴. 앱 서버는 비밀번호를 받지 않습니다 (`external.py` login 에 `action` 파라미터만 추가).
- 프로필 사진: 증빙 관리 종류 목록에서 빼고 내 계정에서 등록 (`/api/me/evidence-files`, kind=photo 그대로 사용).
- 키·몸무게·연락처: `GET/PATCH /api/me/profile` → 중계 `/api/internal/member-profile` → 내부 `/api/internal/my-profile`. 연락처는 가린 값만 내려오고, 바꾸면 이전 승인 연락처 자료는 무효(재다운로드 차단).
- 바뀐 외부 파일: `member_account.py`(ProfileUpdate·중계/BFF 경로), `external.py`(login action), `account.js`(화면), `app.js`(내 계정 탭 항상 표시), `index.html`(증빙 종류에서 사진 제외), `style.css`, 시험 2건 추가.

### 매칭 자격 변경 (11월 15일)
- 필수 증빙이 신분증 + 학력으로 바뀌었습니다. 내부 `matching-directory` 의 `eligible` 은 두 가지 모두 통과해야 true 이고, 화면 열람·일정 확인·반출 검사도 같은 기준입니다. 외부 코드 변경은 없습니다(증빙 종류 목록에 (필수)/(선택)과 상태 표시, 신분증 첫 순서만 바뀜).

### 만남 일정: 회원 간 합의 + 직원 승인 (11월 15일)
- 흐름이 **회원 제안 → 상대 회원 응답 → 담당 직원 승인**으로 바뀌었습니다. 직원 제안 경로(`POST /api/matching/requests/{match_id}/meetings`)는 중계·내부 모두에서 삭제했습니다. 승인(`.../confirm`)·반려(`.../cancel`)·조회는 그대로입니다.
- 회원 제안: `POST /api/me/matches/{match_id}/meetings` (BFF, CSRF) → 중계 `POST /api/internal/matching/requests/{match_id}/meetings` (서비스 토큰 + X-User-Token). 입력은 기존 `{options:[{starts_at,venue,address}]}` 최대 3개. 매칭 당사자만 가능하고, 확정 일정이 있으면 먼저 변경 요청을 보내야 합니다.
- 제안한 회원은 각 후보에 자동으로 '가능' 응답이 기록됩니다. 상대가 같은 후보에 '가능'을 고르면 `both_available=true` → 직원 승인 가능. 회원 응답에는 `proposed_by_me` 가 추가됐습니다.
- 직원 현황(`GET /api/matching/overview`) 각 항목에 `meeting_state`(none·proposed·awaiting_approval·confirmed)를 추가했습니다.
- DB 변경은 없습니다(`proposed_by` 에 회원 user_id 가 들어감). `integrations/internal-scheduling/panel.js` 는 이전 방식(직원 제안) 참고용이며, 실제 직원 화면은 내부 `meeting-staff.js` 를 씁니다.
- 바뀐 외부 파일: `meetings.py`(propose 를 회원용으로), `meeting_routes.py`(회원 제안 경로 추가·직원 제안 삭제), `matching_bff.py`(회원 제안 BFF), `matching_release.py`(`meeting_state`), `external-web/public/meetings.js`(제안 폼), `style.css`, 시험(`test_meetings.py`, `test_matching_release.py`, `meetings.test.cjs`).
- 세부 규칙(11월 15일 추가): 상대는 후보 중 하나만 수락(다른 후보 수락 시 이전 수락은 `change_requested` 로 바뀜), 제안자는 상대 수락 전까지 수정 가능(수락 후 `meeting_already_accepted`). 화면은 빈 후보 무시·부분 입력 차단·보내기 전 확인 창.
- 직원 토큰 검증 수정: 내부 `/api/internal/matching-staff-checks` 가 X-User-Token(직원 토큰)을 `aud=transfer-api` 로 검증합니다. 이전에는 `aud=internal-api` 를 요구해 실제 환경에서 항상 거절됐습니다(외부 코드 변경 없음).

### 승인 자료 표시 (11월 16일)
- 중계 `POST /api/internal/delivery-queries`(회원 제공 자료 목록) 각 항목에 `match_id` 를 추가했습니다(매칭 자료만, 그 외 null).
- 외부 "상대가 허용한 정보"에서 연락처·사진·문서 사본이 승인돼 도착했으면 **승인된 자료 보기** 버튼으로 바로 볼 수 있습니다(기존 "제공 자료" 탭의 자료 보기와 같은 `MaterialUI`). 도착 전에는 기존처럼 "승인 자료로 전달 예정" 안내만 보입니다.
- 바뀐 외부 파일: `transfer.py`(deliveries 에 match_id), `external-web/public/matching.js`, 시험 `test_matching_release.py`.

### 공개 항목 조정: 모든 항목 승인 후 표시 (11월 16일)
- 범위에 `name`(이름) 추가 → `Scope`·`SCOPES`·`Sharing.scopes`(최대 10)·반출 `SUPPORTED`/`ReleaseScope`. 승인 자료에 이름이 있으면 내부가 profile 문구의 "소개 상대"를 실명으로 바꿉니다.
- **모든 항목은 승인 후에만 상대 화면에 보입니다.** 중계 profile 열람(`/api/internal/matching/requests/{id}/profile`)은 이제 값을 주지 않고 `consented_scopes`·`contact_pending`·`approval_required=true` 만 돌려줍니다. 외부 화면 "상대가 허용한 정보"는 이 매칭의 최신 승인 자료(`delivery-queries` 의 `match_id`)를 `MaterialUI.show(..., {compact:true})` 로 보여 줍니다.
- 연락처는 기존대로 상호 연락처 동의 + 일정 확정(`contact_ready`)이 있어야 요청·승인·열람됩니다.
- 바뀐 외부 파일: `matching.py`, `matching_routes.py`, `matching_release.py`, `transfer.py`(deliveries match_id), `matching.js`, `material.js`, 시험(`test_matching.py`, `test_matching_release.py`, `test_services.py`).
