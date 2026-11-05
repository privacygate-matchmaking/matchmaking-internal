# API 명세 (PrivacyGate)

공통 규칙
- 필드 이름은 snake_case. 시간은 UTC(ISO 8601)로 주고받고 화면에서 한국 시간으로 표시한다.
- 사용자 신원(user_id·역할)은 요청 본문이 아니라 **서버 인증 정보**(세션·서명된 토큰)에서 확인한다.
- 브라우저 접속은 HTTPS 만 받는다 (https://localhost:8080 / 8081 / 8090). 쿠키는 Secure.
- 상태를 바꾸는 요청(POST)은 `X-CSRF-Token` 헤더와 Origin 검사를 통과해야 한다.
- 모든 응답에 `X-Trace-Id` 헤더가 붙는다. 감사 로그의 `trace_id` 와 같다.
- 구현 전 경로는 `501 not_implemented` 를 돌려준다. 권한 검사는 501 보다 먼저 일어난다.

## 인증 (internal-api, external-api 각각)
| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | /auth/login | Keycloak 로그인 시작 (Code + PKCE S256, state·nonce) |
| GET | /auth/callback | 코드 교환·ID 토큰 검증 → 세션 쿠키 발급 |
| POST | /auth/logout | 서버 세션 삭제 + Keycloak 로그아웃 주소 반환 |
| GET | /api/me | 현재 사용자 (user_id, pseudo_id, role, csrf_token) |

Keycloak client: `internal-web`, `external-web` · 쿠키: `internal_session`, `external_session` (HttpOnly, SameSite=Strict, Secure)

## 내부 (internal-api)
| 메서드 | 경로 | 허용 역할 | 설명 |
|---|---|---|---|
| GET | /api/members | counselor | 담당 회원 목록 (허용 항목만) |
| GET | /api/members/{member_id} | counselor | 담당 회원 상세. 담당이 아니면 404 |
| POST | /api/admin/member-exports | data_admin | 전체 회원 내보내기 (공격 ① 대상) |
| POST | /api/evidence-files | 서비스: transfer-api + 회원 토큰 | **회원** 증빙 제출 → AES-GCM 암호화 후 evidence-storage (직원은 제출 불가) |
| GET | /api/evidence-files/{file_id}/content | data_admin | 배정된 증빙만, 심사 중에만 열람 |
| POST | /api/evidence-files/{file_id}/review | data_admin | 심사 결과 저장, 원본 삭제 기한 설정 |
| POST | /api/internal/disclosure-checks | 서비스: transfer-api | 수신자-회원 관계·동의 확인 (결과만 응답) |

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

external-api 에는 업무 DB·증빙 저장소 접근 권한이 없다.

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
