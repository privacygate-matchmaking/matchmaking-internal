# API 명세 (PrivacyGate)

공통 규칙
- 필드 이름은 snake_case. 시간은 UTC(ISO 8601)로 주고받고 화면에서 한국 시간으로 표시한다.
- 사용자 신원(user_id·역할)은 요청 본문이 아니라 **서버 인증 정보**(세션·서명된 토큰)에서 확인한다.
- 브라우저 접속은 HTTPS 만 받는다 (https://localhost:8080 / 8081 / 8090). 쿠키는 Secure.
- 상태를 바꾸는 요청(POST)은 `X-CSRF-Token` 헤더와 Origin 검사를 통과해야 한다.
- 모든 응답에 `X-Trace-Id` 헤더가 붙는다. 감사 로그의 `trace_id` 와 같다. 서버 간 호출은 서비스 토큰 검증에 성공한 요청에 한해 받은 `X-Trace-Id`(32자리 hex)를 이어 써서 외부 → 중계 → 내부 로그를 하나로 잇는다.
- ID 는 UUID, 시각은 시간대가 포함된 ISO 8601.
- 구현 전 경로는 `501 not_implemented` 를 돌려준다. 권한 검사는 501 보다 먼저 일어난다.

## 인증 (internal-api, external-api 각각)
| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | /auth/login | Keycloak 로그인 시작 (Code + PKCE S256, state·nonce) |
| GET | /auth/callback | 코드 교환·ID 토큰 검증 → 세션 쿠키 발급 |
| POST | /auth/logout | 서버 세션 삭제 + Keycloak 로그아웃 주소 반환 |
| GET | /api/me | 현재 사용자 (user_id, pseudo_id, role, csrf_token, gate_mode) |

Keycloak client: `internal-web`, `external-web` · 쿠키: `internal_session`, `external_session` (HttpOnly, SameSite=Strict, Secure)

## 내부 (internal-api)
| 메서드 | 경로 | 허용 역할 | 설명 |
|---|---|---|---|
| GET | /api/members | counselor | 담당 회원 목록 (허용 항목만) |
| GET | /api/members/{member_id} | counselor | 담당 회원 상세. 담당이 아니면 404 |
| POST | /api/admin/member-exports | data_admin | 전체 회원 내보내기 (공격 ① 대상). 결과 파일은 서버 내부에만 두고 `export_id`·건수만 응답 (내려받기 경로 없음) |
| POST | /api/member-exports/{export_id}/transfer-files | counselor (본인이 만든 내보내기만) | 내보내기 파일 바이트를 internal-api 가 중계 `POST /api/transfer-files` 에 multipart 로 등록 (공격 연결 단계) ※명세 외 추가 |
| POST | /api/evidence-files | 서비스: transfer-api + 회원 토큰 | **회원** 증빙 제출 (multipart PDF, 최대 2MiB) → AES-GCM 암호화 후 evidence-storage. 201 `{file_id, status}` (직원은 제출 불가) |
| GET | /api/evidence-files | data_admin | 나에게 배정된 증빙 목록 (file_id, 회원 가명 ID, 접수일, 상태, 삭제 기한, 원본 내용 없음) ※명세 외 추가 |
| GET | /api/evidence-files/{file_id}/content | data_admin | 배정된 증빙만, 심사 중에만 열람 |
| POST | /api/evidence-files/{file_id}/review | data_admin | 심사 결과 저장, 원본 삭제 기한 설정 |
| POST | /api/internal/disclosure-checks | 서비스: transfer-api | 수신자-회원 관계·동의 확인 (결과만 응답) |
| GET | /api/internal/my-evidence-files | 서비스: transfer-api + 회원 토큰 | 내 증빙 심사 상태 (원본·심사자 정보 없음) ※명세 외 추가 |
| GET | /api/internal/my-consents | 서비스: transfer-api + 회원 토큰 | 내 동의 목록 ※명세 외 추가 |
| POST | /api/internal/my-consents | 서비스: transfer-api + 회원 토큰 | 동의 등록 (상대 회원·항목·목적·만료) ※명세 외 추가 |
| POST | /api/internal/my-consents/{consent_id}/revoke | 서비스: transfer-api + 회원 토큰 | 동의 철회 ※명세 외 추가 |

## 중계 (transfer-api)
내부 직원 화면은 internal-api 를 거쳐 호출한다 (internal-api 가 1차 역할 확인 후, 서버에 보관한 사용자 access token 을 붙여 전달).

| 메서드 | 경로 | 허용 | 설명 |
|---|---|---|---|
| POST | /api/transfer-files | counselor | transfer-staging 업로드 → 검사 (`scan_status`) |
| POST | /api/export-requests | counselor | 반출 신청 (scan_status=passed 파일만) |
| GET | /api/export-requests | counselor(본인), approver | 신청 목록 |
| GET | /api/export-requests/{request_id} | counselor(본인), approver | 신청 상세 |
| POST | /api/export-requests/{request_id}/approve | approver (신청자 ≠ 승인자) | 승인 → approval_id, delivery_id 생성 |
| POST | /api/export-requests/{request_id}/reject | approver | 거절 |
| POST | /api/approvals/{approval_id}/revoke | approver | 승인 회수 |
| POST | /api/internal/delivery-queries | 서비스: external-api + 회원 토큰 | 회원에게 온 전달 목록 |
| GET | /api/internal/deliveries/{delivery_id}/download | 서비스: external-api + 회원 토큰 | 승인 파일 다운로드 |
| POST | /api/internal/evidence-submissions | 서비스: external-api + 회원 토큰 | 회원 증빙을 internal-api 로 전달만 (중계에 저장 안 함) ※명세 외 추가 |
| GET | /api/internal/evidence-submissions | 서비스: external-api + 회원 토큰 | 내 증빙 심사 상태 전달 ※명세 외 추가 |
| GET·POST | /api/internal/member-consents | 서비스: external-api + 회원 토큰 | 내 동의 목록·등록 전달 ※명세 외 추가 |
| POST | /api/internal/member-consents/{consent_id}/revoke | 서비스: external-api + 회원 토큰 | 동의 철회 전달 ※명세 외 추가 |

- 검사 통과(`passed`)와 제공 승인(`approved`)은 별개다. 반출 금지 자료는 승인으로도 허용되지 않는다.
- 직원 승인과 회원 동의를 각각 확인한다 (동의는 disclosure-checks 로 internal-api 에 질의).
- 다운로드는 `delivery_id` 기준으로 **서버가** 승인된 file_id·file_version·file_hash 를 고른다. 요청의 file_id 는 따르지 않는다 (공격 ② 차단).
- external-api 가 전달하는 사용자 정보는 Keycloak 이 서명한 회원 access token(aud=transfer-api)이다. 단순 user_id 문자열은 믿지 않는다.

## 외부 (external-api)
| 메서드 | 경로 | 허용 | 설명 |
|---|---|---|---|
| GET | /api/me/deliveries | member | 나에게 온 전달 목록 (transfer-api 경유) |
| GET | /api/me/deliveries/{delivery_id}/download | member | 승인 파일 다운로드 (transfer-api 경유) |
| POST | /api/me/evidence-files | member | 증빙 제출 (transfer-api → internal-api 경유) ※명세 외 추가 |
| GET | /api/me/evidence-files | member | 내 증빙 심사 상태 ※명세 외 추가 |
| GET·POST | /api/me/consents | member | 내 동의 목록·등록 ※명세 외 추가 |
| POST | /api/me/consents/{consent_id}/revoke | member | 동의 철회 ※명세 외 추가 |

external-api 에는 업무 DB·증빙 저장소 접근 권한이 없다.

## 동작 모드 (`GATE_MODE`)
- `enforce`(기본): 모든 통제 적용.
- `baseline`(시연 비교용): 공격 ①② 대상 통제만 끈다. ① `POST /api/admin/member-exports` 역할 검사 → 로그인한 직원이면 통과, ② 다운로드의 "요청 file_id ↔ 승인 파일" 연결 검사만 생략 (승인·수신자·동의·만료·승인 파일 무결성 검사는 그대로) → 요청 file_id 의 파일 제공. 로그인·세션·CSRF·감사 로그는 그대로이며, 통제를 건너뛴 요청은 감사 로그 reason 에 `baseline_role_check_off` 등으로 남는다. 내부 화면 상단에 경고가 표시된다.

## 응답 형식 (외부·중계 연동 계약 v0.5 기준)

| 경로 | 입력 → 응답 |
|---|---|
| `GET /api/members` | → `{"items": [{member_id, pseudo_id, birth_year, job}]}` (담당 회원만) |
| `GET /api/members/{member_id}` | → `{member_id, pseudo_id, birth_year, job, consents: [{consent_id, item, purpose, counterpart_pseudo_id, recipient_id, expires_at, revoked_at, valid}]}`. 담당 아니면 404 |
| `POST /api/admin/member-exports` | `{}` → 201 `{export_id, row_count, created_at}` (파일은 evidence-storage/exports 에 암호문) |
| `POST /api/member-exports/{export_id}/transfer-files` | `{}` → 중계 응답 그대로 (`{file_id, scan_status, export_banned, ...}`). 이미 등록했으면 409 |
| `GET /api/evidence-files` | → `{"items": [{file_id, member_pseudo_id, status, review_result, created_at, delete_after, legal_hold}]}` |
| `GET /api/evidence-files/{file_id}/content` | → `application/pdf` (no-store, sandbox CSP). submitted → in_review 로 바뀜 |
| `POST /api/evidence-files/{file_id}/review` | `{"result": "passed"\|"rejected"}` → `{file_id, status: "reviewed", review_result, delete_after}` (삭제 기한 +7일) |
| `POST /api/internal/disclosure-checks` | `{member_id, recipient_id, consent_id, purpose, item}` → 허용 `{"allowed": true, "expires_at", "member_pseudo_id"}`, 거부 `{"allowed": false}` 또는 공통 403. 조회 실패·미구현을 허용으로 해석하지 않음. 신청·승인·다운로드마다 재호출 |
| `POST /api/evidence-files` | multipart PDF(≤2MiB) → 201 `{file_id, status}` |
| `GET /api/internal/my-evidence-files` | → `{"items": [{file_id, status, created_at, review_result?}]}` (status: submitted / in_review / reviewed / deleted) |
| `GET /api/internal/my-consents` | → `{"items": [{consent_id, counterpart_pseudo_id, item, purpose, expires_at, revoked_at}], "counterparts": [{counterpart_member_id, counterpart_pseudo_id}]}` (counterparts = 소개된 상대만, `introductions` 테이블) |
| `POST /api/internal/my-consents` | `{counterpart_member_id, item, purpose, expires_at}` → 201 `{consent_id, ...}`. 소개된 상대인지 내부에서 확인 |
| `POST /api/internal/my-consents/{consent_id}/revoke` | `{}` → `{consent_id, revoked_at}`. 본인 동의인지 확인 |
| `POST /api/transfer-files` (중계) | multipart file → 201 `{file_id, file_version, file_hash, scan_status, export_banned}`. 스키마 밖 파일(CSV 등)은 blocked·export_banned |
| `POST /api/export-requests` (중계) | `{file_id, member_id, recipient_id, consent_id, purpose, expires_at}` → 201 `{request_id}`. 반출 기한 최대 7일, 동의 만료를 넘을 수 없음 |
| `POST /api/export-requests/{request_id}/approve` (중계) | `{}` → `{request_id, approval_id, delivery_id, expires_at}` |

정상 승인 대상 소개 JSON 키: `member_pseudo_id`, `age_band`, `job_group`, `introduction` (각 1~300자). purpose 는 `introduction`, 동의 item 은 `profile`/`photo`/`contact` (소개 자료 반출은 profile).

## 상태 값
- `scan_status`: pending / passed / blocked / error
- `request_status`: pending / approved / rejected / revoked / expired

## 오류 응답
```json
{"error": {"code": "ACCESS_DENIED", "message": "이 작업을 할 권한이 없습니다.", "trace_id": "..."}}
```
| HTTP | code | 의미 |
|---|---|---|
| 401 | AUTH_REQUIRED | 로그인·서비스 토큰 없음 또는 만료 |
| 403 | ACCESS_DENIED | 역할·소유·CSRF 불일치 |
| 403 | APPROVAL_MISMATCH | 승인 건과 수신자·파일이 다름 |
| 403 | APPROVAL_EXPIRED | 승인 기한 지남 |
| 403 | CONSENT_INVALID | 회원 동의 없음·철회·만료 |
| 409 | INVALID_STATE | 현재 상태에서 할 수 없는 작업 |
| 404 | NOT_FOUND | 없음 (또는 존재를 공개하지 않음) |
| 422 | INVALID_REQUEST | 입력 형식 오류 |
| 500 | INTERNAL_ERROR | 서버 오류 |

판단 근거(reason)는 응답에 넣지 않고 감사 로그에만 남긴다.
