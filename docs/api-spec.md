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
| GET | /api/members | counselor(담당 회원), data_admin(전체) | 회원 목록 (허용 항목·담당 직원·상태, 이름·연락처 제외) |
| GET | /api/members/{member_id} | counselor(담당 회원), data_admin(전체) | 회원 상세(동의·매칭 현황). 범위 밖이면 404 |
| POST | /api/admin/member-exports | data_admin | 전체 회원 내보내기 (공격 ① 대상). 결과 파일은 서버 내부에만 두고 `export_id`·건수만 응답 (내려받기 경로 없음) |
| PATCH | /api/members/{member_id} | counselor(담당 회원), data_admin(전체) | 회원 정보 수정 — 출생연도·직업만, 탈퇴 회원 불가 ※명세 외 추가 |
| POST | /api/members/{member_id}/introductions | counselor(담당 회원) | 매칭 동의(consent_id)로 소개 자료 발송 요청. 서버가 회원 DB 로 소개 JSON 을 만들어 중계에 등록·신청 (직원 업로드 없음) ※명세 외 추가 |
| POST | /api/members/{member_id}/withdraw | counselor(담당 회원), data_admin(전체) | 탈퇴: `scheduled` = 7일 유예(탈퇴 예정, 기한 후 자동 삭제, 사유 선택 입력), `immediate` = 즉시 삭제(**data_admin 만**). 삭제는 DB 함수 `purge_member` 로 회원·동의·매칭·증빙(파일 포함)·소개 자료 기록을 지움 ※명세 외 추가 |
| POST | /api/members/{member_id}/withdraw/cancel | counselor(담당 회원), data_admin(전체) | 탈퇴 철회 (유예 중에만). data_admin 이 요청한 탈퇴는 data_admin 만 철회 ※명세 외 추가 |
| GET | /api/admin/member-exports | data_admin (총관리자) | 전체 회원 내보내기 내역 (실행 직원·건수·중계 등록 여부, 파일 내용 없음) ※명세 외 추가 |
| POST | /api/member-exports/{export_id}/transfer-files | counselor (본인이 만든 내보내기만) | 내보내기 파일 바이트를 internal-api 가 중계 `POST /api/transfer-files` 에 multipart 로 등록 (공격 연결 단계) ※명세 외 추가 |
| POST | /api/evidence-files | 서비스: transfer-api + 회원 토큰 | **회원** 증빙 제출 (multipart, 최대 2MiB, `kind` = education·employment·identity·marital·income·property 는 PDF, photo 는 JPEG/PNG) → AES-GCM 암호화 후 evidence-storage, 자동 검사 대기. 201 `{file_id, kind, status}` (직원은 제출 불가) |
| GET | /api/evidence-files | counselor(담당 회원), data_admin(전체) | 증빙 목록 (file_id, 회원 가명 ID, 접수일, 상태, 심사자, 삭제 기한, 원본 내용 없음) ※명세 외 추가 |
| GET | /api/evidence-files/{file_id}/content | counselor(담당 회원), data_admin(전체) | 심사 중에만 열람, 처음 연 직원이 심사자 |
| POST | /api/evidence-files/{file_id}/review | counselor(담당 회원), data_admin(전체) | 심사 결과(통과·반려) 저장, 원본 삭제 기한 설정. 통과 시 공개 결과(요약·마스킹 사본) 생성 |
| GET | /api/evidence-files/{file_id}/inspection | counselor(담당 회원), data_admin(전체) | 자동 검사 결과: 진위 판단(발급대장 대조), 개인정보 탐지 건수, 추출 값(직원 확인용), 공개 사실 제안 ※명세 외 추가 |
| GET | /api/evidence-files/{file_id}/masked | counselor(담당 회원), data_admin(전체) | 마스킹 사본(PNG)·검토 사진(JPEG) 미리보기 ※명세 외 추가 |
| POST | /api/evidence-files/{file_id}/inspect | counselor(담당 회원), data_admin(전체) + CSRF | 자동 검사 다시 실행 (심사 전 증빙만) ※명세 외 추가 |
| POST | /api/internal/disclosure-checks | 서비스: transfer-api | 수신자-회원 관계·동의 확인 (결과만 응답) |
| GET | /api/internal/my-evidence-files | 서비스: transfer-api + 회원 토큰 | 내 증빙 심사 상태 (원본·심사자 정보 없음) ※명세 외 추가 |
| GET | /api/internal/my-profile | 서비스: transfer-api + 회원 토큰 | 내 계정: 키·몸무게, 가린 연락처, 프로필 사진 검토 상태 ※명세 외 추가 |
| PATCH | /api/internal/my-profile | 서비스: transfer-api + 회원 토큰 | 키(120~230)·몸무게(30~200)·휴대전화·이메일 변경 (보낸 항목만), 담당 직원 알림 ※명세 외 추가 |
| POST | /api/internal/member-notification-events | 서비스: transfer-api 만 (회원 토큰 없음) | 회원 알림 사건 `{user_ids:[최대 2], kind}`. kind: match_requested·match_accepted·match_rejected·match_cancelled·match_ended·meeting_proposed·meeting_accepted·meeting_change_requested·meeting_confirmed·meeting_cancelled·release_approved·release_revoked. 문구는 내부가 정함, 활성 회원 계정에만 저장 ※명세 외 추가 |
| GET | /api/internal/my-notifications | 서비스: transfer-api + 회원 토큰 | 내 알림 `{unread, items:[{notification_id, kind, title, body, link_view, created_at, read}]}` (최근 100건) ※명세 외 추가 |
| POST | /api/internal/my-notifications/read · /delete | 서비스: transfer-api + 회원 토큰 | `{ids:[], all:false}` → 본인 알림만 읽음·삭제 ※명세 외 추가 |
| GET | /api/internal/my-status | 서비스: transfer-api + 회원 토큰 (회원 행 없어도 됨) | 내 계정 상태·탈퇴 안내 문구. 외부 화면은 로그인 직후 호출 ※명세 외 추가 |
| POST | /api/staff-signups | 로그인 전 (Origin 일치 + 접속 주소당 10분 5회·전체 30회) | 직원 가입 신청 `{username, password, name, email, requested_role: counselor\|approver}` → 201 `{status:"pending"}`. Keycloak 계정은 비활성·역할 없음 ※명세 외 추가 |
| GET | /api/staff-signups | data_admin | 대기 중 가입 신청 목록 `{items:[{signup_id, username, name, email, requested_role, created_at}]}` ※명세 외 추가 |
| POST | /api/staff-signups/{signup_id}/approve | data_admin + CSRF | 승인: Keycloak 활성화 + 역할 그룹, users 등록 → `{status:"approved", pseudo_id, role, username}` ※명세 외 추가 |
| POST | /api/staff-signups/{signup_id}/reject | data_admin + CSRF | 거절: Keycloak 계정·신청 기록 삭제 → `{status:"rejected"}` ※명세 외 추가 |
| POST | /api/internal/member-signups | 서비스: transfer-api 만 (회원 토큰 없음) | 회원가입: 입력 검사 → Keycloak 계정 생성(members 그룹) → `register_member` 로 회원 저장·담당 자동 배정. 실패 시 계정 되돌림 ※명세 외 추가 |
| POST | /api/internal/my-withdrawal | 서비스: transfer-api + 회원 토큰 | 회원 본인 탈퇴 신청 (7일 유예) ※명세 외 추가 |
| POST | /api/internal/my-withdrawal/cancel | 서비스: transfer-api + 회원 토큰 | 본인이 신청한 탈퇴만 철회 (직원 처리 건은 403) ※명세 외 추가 |
| GET | /api/internal/my-consents | 서비스: transfer-api + 회원 토큰 | 내 동의 목록 ※명세 외 추가 |
| POST | /api/internal/my-consents | 서비스: transfer-api + 회원 토큰 | 동의 등록 (상대 회원·항목·목적·만료) ※명세 외 추가 |
| POST | /api/internal/my-consents/{consent_id}/revoke | 서비스: transfer-api + 회원 토큰 | 동의 철회 ※명세 외 추가 |
| GET | /api/admin/security-incidents?status=open\|all | data_admin | 보안 사건 목록 `{items:[{incident_id, kind, title, severity, subject_code, subject_role, source, detail, trace_id, blocked, occurrences, auto_locked_until, status, note, first_seen_at, last_seen_at, subject:{exists, active, locked_until}}], counts}` (이름·연락처 없음) ※사후 대응 |
| GET | /api/admin/security-incidents/{incident_id} | data_admin | 사건 상세 + 조치 기록 `actions:[{action, result, detail, actor, created_at}]` ※사후 대응 |
| POST | /api/admin/security-incidents/{incident_id}/status | data_admin + CSRF | 검토 상태 `{status: new\|reviewing\|resolved\|false_positive, note}` ※사후 대응 |
| POST | /api/admin/security-incidents/{incident_id}/actions | data_admin + CSRF | 조치 `{action, note}`: `unlock`(임시 잠금 해제) · `suspend_account`(users.active=false + 직원 세션 삭제 + Keycloak 비활성·세션 종료, 본인·총관리자 불가 409) · `restore_account`(복구 + 잠금 해제) · `revoke_deliveries`(회원 대상 사건만: 중계에서 그 회원이 받은 승인 모두 회수). 첫 조치 시 상태 new → reviewing ※사후 대응 |
| POST | /api/internal/security-events | 서비스: transfer-api + 회원 토큰 | 중계가 알리는 공격 ②·토큰 오용 `{kind:"approval_mismatch"\|"download_token_misuse", reason, blocked, delivery_id}` → 보안 사건(토큰 생략은 medium, 그 외 high), 같은 회원·같은 종류 60초 3회면 15분 잠금 `{incident_id, locked_until, newly_locked}`. 대상 회원은 본문이 아니라 회원 토큰으로 정한다 ※사후 대응 |

## 사후 대응 (자동 임시 잠금·보안 사건)
- **자동 임시 잠금**: 직원이 역할 밖 경로를 60초 안에 3번 요청(`role_not_allowed`)하거나, 회원의 승인 외 자료 요청을 중계가 60초 안에 3번 알리면 그 계정을 15분 잠근다. 잠긴 직원은 모든 업무 API 가 403 `account_temporarily_locked`(안내 문구에 해제 시각), 잠긴 회원은 `my-status` 가 `locked` 를 돌려줘 중계가 회원 기능을 막는다.
- **보안 사건**: 공격 ①(상담 직원의 관리자 내보내기)은 첫 시도부터, 공격 ②는 중계 알림마다 사건으로 남는다(같은 계정·종류의 열린 사건이 10분 안이면 횟수만 증가). baseline 에서 통과한 시도도 `blocked=false` 사건으로 남는다 (탐지는 되지만 막지 못함).
- **계정 정지**: 업무 DB `users.active` 변경은 SECURITY DEFINER 함수 `set_account_active` 로만 (앱 계정에 users UPDATE 권한 없음). 정지된 회원은 `my-status` 가 `suspended`.
- 사건·잠금 처리 실패는 차단 결정을 바꾸지 않는다 (거부 응답은 그대로). 감사 로그 파일(Wazuh 수집)·감사 DB 기록이 실패해도 차단·잠금은 동작한다.
- 감사 로그: `security.auto_lock`, `security.unlock` · `security.suspend_account` · `security.restore_account` · `security.revoke_deliveries`, `security.incident_status`, 중계 `security.report`. Wazuh 규칙 100150~100153.

## 감사 로그 공통 형식·위변조 방지 (보안 강화)
- 모든 서비스(내부·외부·중계)가 privacygate `AuditWriter` 로 같은 형식을 쓴다: `ts, service, trace_id, actor, role, action, target_type, target_id, result, reason, policy_version` + 자료 제공 시 `owner_id, recipient_id, consent_id, approval_id, file_id, file_hash`. 비밀번호·세션·토큰 원문·주민번호·연락처는 필드가 없어 기록할 수 없다.
- JSON 파일 각 줄에 `seq, prev_hash, hash` (SHA-256 해시 체인). `infra/scripts/audit-verify.sh` 가 수정·삭제·순서 변경·누락을 찾아 `audit-verifier.json` 에 결과를 남긴다 (Wazuh 100160·100161). 파일은 0640.
- 앵커: `audit-verify.sh` 가 검사마다 파일별 마지막 `(seq, hash)` 를 business DB `audit_anchors`(app_user SELECT·INSERT, 트리거로 수정·삭제·TRUNCATE 불가)에 남기고 이전 앵커와 대조 → 체인 재계산·잘라내기 탐지 (`audit_anchor_mismatch`, Wazuh 100162). 정당한 초기화는 db_owner 가 `audit_anchor_resets` 에 기록 (앱 계정은 읽기만).
- mTLS 호출자 고정(`MTLS_PEER_POLICY=internal-api`): `/api/internal/*` 은 transfer-api 인증서만, 나머지는 internal-web 인증서만. 위반은 403 + 감사 `mtls_peer_not_allowed` (actor `svc:<CN>`, Wazuh 100178). internal-web nginx 는 `/api/internal/` 을 404 로 막는다.
- DB `audit_log` (업무·중계): 앱 계정은 INSERT 만, 트리거로 DB 소유자도 UPDATE·DELETE·TRUNCATE 불가. 보관기간(365일 이상) 지난 행만 `SELECT purge_audit_log(365)` (운영자).
- Keycloak 로그인 실패·직원 로그인·역할/그룹 변경 이벤트를 internal-api 가 30초마다 읽어 같은 형식(`keycloak.*`)으로 남긴다 (Wazuh 100180~100183). IP·비밀번호는 남기지 않는다.

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
| POST | /api/internal/deliveries/{delivery_id}/download-tokens | 서비스: external-api + 회원 토큰 | 일회용 다운로드 토큰 발급 `{token, expires_in, required}` — 다운로드와 같은 판단(수신자·승인·회수·동의·만료·파일 ID/버전/해시·검사·횟수)을 먼저 하고, 원문은 응답에만·DB 에는 SHA-256 만. 같은 제공 건의 이전 미사용 토큰은 폐기 ※보안 강화 |
| GET | /api/internal/deliveries/{delivery_id}/download | 서비스: external-api + 회원 토큰 (+ `X-Download-Token`) | 승인 파일 다운로드. enforce 는 토큰 필수(60초·1회, 재사용 403 `download_token_used`), 제공 건당 최대 5회(`download_limit_reached`). 승인 외 file_id 요청은 토큰과 무관하게 먼저 `requested_file_not_approved` |
| POST | /api/internal/evidence-submissions | 서비스: external-api + 회원 토큰 | 회원 증빙을 internal-api 로 전달만 (중계에 저장 안 함) ※명세 외 추가 |
| GET | /api/internal/evidence-submissions | 서비스: external-api + 회원 토큰 | 내 증빙 심사 상태 전달 ※명세 외 추가 |
| GET·POST | /api/internal/member-consents | 서비스: external-api + 회원 토큰 | 내 동의 목록·등록 전달 ※명세 외 추가 |
| POST | /api/internal/member-consents/{consent_id}/revoke | 서비스: external-api + 회원 토큰 | 동의 철회 전달 ※명세 외 추가 |
| POST | /api/security/recipients/{user_id}/revoke-deliveries | data_admin (internal-api 사건 화면 경유) | 그 회원이 받은 승인 자료를 모두 회수 `{recipient_id, revoked}` ※사후 대응 |

- 검사 통과(`passed`)와 제공 승인(`approved`)은 별개다. 반출 금지 자료는 승인으로도 허용되지 않는다.
- 직원 승인과 회원 동의를 각각 확인한다 (동의는 disclosure-checks 로 internal-api 에 질의).
- 다운로드는 `delivery_id` 기준으로 **서버가** 승인된 file_id·file_version·file_hash 를 고른다. 요청의 file_id 는 따르지 않는다 (공격 ② 차단).
- external-api 가 전달하는 사용자 정보는 Keycloak 이 서명한 회원 access token(aud=transfer-api)이다. 단순 user_id 문자열은 믿지 않는다.
- 다운로드가 `requested_file_not_approved`·`recipient_mismatch` 로 거부되면 internal-api `POST /api/internal/security-events` 로 알린다 (회원 토큰 함께). baseline 에서 바꿔치기 파일을 내준 경우는 `blocked=false` 로 알린다. 알림 실패는 감사 로그 `security.report` error 로만 남고 거부는 그대로다.
- 토큰 오용 대응: `download_token_used`(내려받기에 쓴 토큰 재사용)·`download_token_invalid`(위조·다른 건 토큰)·`download_token_required`(토큰 없이 직접 호출)로 거부되면 ① 그 제공 건의 남은 토큰을 즉시 폐기(`revoked_at`, 감사 `security.token_containment`, Wazuh 100154) ② internal-api 에 `kind=download_token_misuse` 로 알린다(60초 3회면 15분 잠금). 새 토큰 발급·회수·보안 조치로 폐기된 토큰은 `download_token_revoked`(정상 사용자도 겪을 수 있어 오용으로 세지 않음), 만료는 `download_token_expired`.
- 무결성 불일치 대응: 저장소 파일 해시가 승인 해시와 다르면(`actual_file_hash_mismatch`) 그 파일을 `export_banned=true, scan_reason=integrity_quarantine` 로 격리한다 (감사 `security.file_quarantine`, Wazuh 100121). 원본을 되돌려도 격리는 유지되며, 운영자가 해시 일치를 확인한 뒤 해제한다 (`hardening/file-tamper.sh release`).
- mTLS 호출자 고정(`MTLS_PEER_POLICY=transfer-api`): `/api/internal/*` 은 external-api 인증서만, 나머지(반출·승인·매칭 관리)는 internal-api 인증서만. 위반은 403 + 감사 `mtls_peer_not_allowed` (Wazuh 100178).

## 외부 (external-api)
| 메서드 | 경로 | 허용 | 설명 |
|---|---|---|---|
| GET | /api/me/deliveries | member | 나에게 온 전달 목록 (transfer-api 경유) |
| POST | /api/me/deliveries/{delivery_id}/download-token | member + CSRF | 일회용 다운로드 토큰 받기 (transfer-api 경유) ※보안 강화 |
| GET | /api/me/deliveries/{delivery_id}/download | member (+ `X-Download-Token`) | 승인 파일 다운로드 (transfer-api 경유). 토큰은 주소가 아니라 헤더로만 보낸다 |
| POST | /api/me/evidence-files | member | 증빙 제출 (transfer-api → internal-api 경유) ※명세 외 추가 |
| GET | /api/me/evidence-files | member | 내 증빙 심사 상태 ※명세 외 추가 |
| GET·POST | /api/me/consents | member | 내 동의 목록·등록 ※명세 외 추가 |
| POST | /api/me/consents/{consent_id}/revoke | member | 동의 철회 ※명세 외 추가 |
| POST | /api/signup | 로그인 전 (Origin 일치 + 접속 주소당 10분 5회·전체 60회) | 회원가입 → 중계 `POST /api/internal/member-signups`(external-api 서비스 토큰) → 내부 ※명세 외 추가 |

external-api 에는 업무 DB·증빙 저장소 접근 권한이 없다.

## 동작 모드 (`GATE_MODE`)
- `enforce`(기본): 모든 통제 적용.
- `baseline`(시연 비교용): 공격 ①② 대상 통제만 끈다. ① `POST /api/admin/member-exports` 역할 검사 → 로그인한 직원이면 통과, ② 다운로드의 "요청 file_id ↔ 승인 파일" 연결 검사만 생략 (승인·수신자·동의·만료·승인 파일 무결성 검사는 그대로) → 요청 file_id 의 파일 제공. 로그인·세션·CSRF·감사 로그는 그대로이며, 통제를 건너뛴 요청은 감사 로그 reason 에 `baseline_role_check_off` 등으로 남는다. 내부 화면 상단에 경고가 표시된다.

## 응답 형식 (외부·중계 연동 계약 v0.5 기준)

| 경로 | 입력 → 응답 |
|---|---|
| `GET /api/members/{member_id}` | → 회원 프로필(목록과 같은 항목) (status: active·withdraw_pending, withdraw_at 포함) `consents: [{consent_id, consent_label, item, purpose, counterpart_pseudo_id, recipient_id, expires_at, revoked_at, valid}]`, `matches: [{counterpart_member_id, counterpart_pseudo_id, counterpart_label, card, i_matched, they_matched, matched}]` (직원용이라 회원 코드 포함), `verified_evidence: [{kind, summary, reviewed_at}]`(종류별 최신 통과 결과 요약만, 예: "연소득 구간: 5천만~7천만원"), `membership: {available, paid, plan:{name,credits,months}, wallet:{active,total,reserved,used,available,expires_at}, last_paid_at, orders(최근 5건: plan_code, amount_won, status, created_at, paid_at)}` (중계 `GET /api/matching/members/{user_id}/membership` 결과, 실패 시 `{available:false, reason: no_account\|transfer_unreachable\|transfer_<상태>}`, 상세는 그대로 열림). 범위 밖이면 404 |
| `GET /api/members` | → `{"items": [{member_id, pseudo_id, name, gender, birth_date, age, height_cm, weight_kg, education_level, school, major, job_group, company, introduction, education_verified, employment_verified, status, has_account, counselors, valid_consents, open_evidence, created_at}]}` (연락처 제외. counselor: 담당 회원, data_admin: 전체) |
| `PATCH /api/members/{member_id}` | `{name?, gender?, birth_date?, height_cm?, weight_kg?, education_level?, school?, major?, job_group?, company?, introduction?}` → 회원 프로필. 학력 항목 변경 시 `education_verified=false`, 직장 변경 시 `employment_verified=false` |
| `POST /api/members/{member_id}/introductions` | `{consent_id}` → 201 `{request_id, request_status, created_at, label, file_id, profile}` (label = 관리자 화면용 이름 `A-001_file1`, 중계 파일 이름도 같음) (profile = 중계에 보낸 소개 JSON) |
| `POST /api/members/{member_id}/withdraw` | `{"mode": "scheduled"\|"immediate", "reason"?: "≤200자"}` → scheduled: `{member_id, status: "withdraw_pending", withdraw_at}`, immediate: `{member_id, status: "deleted", deleted_evidence_files}` |
| `POST /api/members/{member_id}/withdraw/cancel` | `{}` → `{member_id, status: "active"}` |
| `GET /api/internal/my-matches` | → `{"can_match": bool, "items": [{counterpart_member_id, counterpart_label, card: {age, height_cm, weight_kg, education_level, introduction}, i_matched, they_matched, matched, matched_at}]}` (card = 매칭 전 공개 정보, 회원 코드·실명 없음. can_match = 내 학력 증빙 통과 여부) |
| `POST /api/internal/my-matches` | `{counterpart_member_id}` → 201 `{counterpart_member_id, matched}`. 학력 증빙 미통과면 409 `education_not_verified`. 서로 누르면 양쪽 프로필 제공 동의(item=profile, purpose=introduction, 30일) 자동 생성 |
| `POST /api/internal/my-matches/{counterpart_member_id}/cancel` | `{}` → `{counterpart_member_id, cancelled, revoked_consents}`. 매칭으로 만든 양쪽 동의 철회 |
| `GET /api/admin/member-exports` | → `{"items": [{export_id, created_by, created_by_role, row_count, transfer_file_id, created_at}]}` (최근 50건) |
| `POST /api/admin/member-exports` | `{}` → 201 `{export_id, row_count, created_at}` (파일은 evidence-storage/exports 에 암호문) |
| `POST /api/member-exports/{export_id}/transfer-files` | `{}` → 중계 응답 그대로 (`{file_id, scan_status, export_banned, ...}`). 이미 등록했으면 409 |
| `GET /api/evidence-files` | → `{"items": [{file_id, member_pseudo_id, status, review_result, created_at, delete_after, legal_hold}]}` |
| `GET /api/evidence-files/{file_id}/content` | → `application/pdf` (no-store, sandbox CSP). submitted → in_review 로 바뀜 |
| `POST /api/evidence-files/{file_id}/review` | `{"result": "passed"\|"rejected", "facts"?: {...}}` → `{file_id, status: "reviewed", review_result, delete_after}` (삭제 기한 +7일). 통과 시 `facts` 필수: 혼인 `{status: 미혼\|이혼\|사별}`, 소득 `{band: 3천만원 미만…1억원 이상}`, 부동산 `{owns: true, region: 시·도}` 또는 `{owns: false}` |
| 증빙 파일 이름 | 회원이 올린 파일 이름은 쓰지 않고 서버가 `A-003(박도윤)_education.pdf` 형식으로 정해 `evidence_files.file_name` 에 저장. 직원 목록·심사 화면·원본 열람 응답(Content-Disposition)에만 쓰이며 저장 경로는 UUID 그대로 |
| `GET /api/evidence-files/{file_id}/inspection` | → `{status: pending\|done\|failed, verdict: verified\|suspicious\|unchecked, checks: {issue_format, issue_checksum, registry_found, registry_kind, name_match, birth_match, registry_revoked}, detected: {resident_number: 1, …}, fields: {name, birth, issue_no, amount…}, proposed, summary, has_masked, options}` |
| `POST /api/internal/matching-disclosures` | 화면 열람용. 텍스트 범위 + `name`(동의 시 profile 의 '소개 상대'를 실명으로, profile 없으면 name 항목) + `contact`(요청 body `contact_ready=true` 이고 신분증 통과·연락처 등록 시) |
| `POST /api/internal/matching-directory` (후보 범위) | 직원 소개 관계(`introductions`) 또는 **성별이 다른** 활동 회원(회원 계정 연결). 담당 직원이 달라도 후보. `eligible` = 신분증·학력·프로필 사진·혼인관계증명서 최신 심사 통과(매칭 필수 조건), 본인 카드(`self`)에만 `requirements: {identity, education, photo, marital}`, 후보 카드에 `marital_status`(통과한 혼인관계 심사의 상태, 아니면 null). 최대 100명, 가입 순. 공개 열람·반출·일정 확인의 관계 검사도 같은 기준 |
| `POST /api/matching/requests/{match_id}/end` | 상담 직원 BFF(CSRF) → 중계 같은 경로. 관계 종료 |
| `PATCH /api/internal/my-profile` 소개글 | `introduction`(10~300자, 공백 정리) 추가. 전화번호·이메일·링크·메신저 아이디가 있으면 422 `introduction_contact`. `GET` 응답에도 `introduction`. 후보 카드에 `height_cm`·`weight_kg`(본인 신고) 추가, `introduction` = 회원 소개글(없으면 안내 문구, 연락 수단이 섞인 예전 글은 "소개글을 확인 중입니다.") |
| `POST /api/internal/member-scope-checks` | 중계(transfer-api 서비스 토큰) + X-User-Token(직원 토큰, counselor·data_admin) `{user_id}` → `{allowed}`. 총관리자이거나 그 회원의 담당 상담 직원이면 true (회원 이용권 정보 조회 전 확인) |
| `POST /api/internal/matching-release-checks` | 범위: profile·education·employment·income·marital_status·property(텍스트), photo(검토 사진), documents(함께 선택한 서류의 마스킹 사본), contact(신분증 통과 + 연락처 등록, 상호 동의·일정 확정은 중계가 확인). 사진·사본은 `attachments: [{name, label, media_type, sha256, data_base64}]` |
| `POST /api/internal/disclosure-checks` | `{member_id, recipient_id, consent_id, purpose, item}` → 허용 `{"allowed": true, "expires_at", "member_pseudo_id"}`, 거부 `{"allowed": false}` 또는 공통 403. 조회 실패·미구현을 허용으로 해석하지 않음. 신청·승인·다운로드마다 재호출 |
| `POST /api/evidence-files` | multipart `file`(PDF ≤2MiB) + `kind`(`education`=졸업증명서 / `employment`=재직증명서, 생략 시 education) → 201 `{file_id, kind, status}`. 통과 시 학력 → 매칭 가능, 재직 → 소개 자료에 직장 포함 |
| `GET /api/internal/my-status` | → `{"status": "active"\|"withdraw_pending"\|"withdrawn"\|"not_registered", "by"?: "self"\|"staff", "reason"?: (직원 처리 건만), "withdraw_at"?, "withdrawn_at"?, "can_cancel"?, "message": "화면에 그대로 보여 줄 문구"}`. 예: 직원 처리 확정 "관리자에 의해 탈퇴 처리된 계정입니다. 사유: …", 본인 탈퇴 확정 "탈퇴된 계정입니다." 탈퇴 확정 후 안내 기간(기본 30일)이 지나면 Keycloak 계정이 삭제되어 로그인 자체가 안 됨 |
| `POST /api/internal/my-withdrawal` | `{"reason"?: "≤200자"}` → `{status: "withdraw_pending", withdraw_at}`. 이미 유예 중이면 409 |
| `POST /api/internal/my-withdrawal/cancel` | `{}` → `{status: "active"}`. 유예 중 아님 409, 직원이 처리한 탈퇴 403 `withdraw_requested_by_staff` |
| `GET /api/internal/my-evidence-files` | → `{"items": [{file_id, status, created_at, review_result?}]}` (status: submitted / in_review / reviewed / deleted) |
| `GET /api/internal/my-consents` | → `{"items": [{consent_id, consent_label, counterpart_label, item, purpose, expires_at, revoked_at}], "counterparts": [{counterpart_member_id, counterpart_label}]}` (counterpart_label 예: "소개 상대 · 만 32세 · 4년제 대졸", 회원 코드는 주지 않음) (counterparts = 소개된 상대만, `introductions` 테이블) |
| `POST /api/internal/my-consents` | `{counterpart_member_id, item, purpose, expires_at}` → 201 `{consent_id, ...}`. 소개된 상대인지 내부에서 확인 |
| `POST /api/internal/my-consents/{consent_id}/revoke` | `{}` → `{consent_id, revoked_at}`. 본인 동의인지 확인 |
| `POST /api/transfer-files` (중계) | multipart file → 201 `{file_id, file_version, file_hash, scan_status, export_banned}`. 스키마 밖 파일(CSV 등)은 blocked·export_banned |
| `POST /api/export-requests` (중계) | `{file_id, member_id, recipient_id, consent_id, purpose, expires_at}` → 201 `{request_id}`. 반출 기한 최대 7일, 동의 만료를 넘을 수 없음 |
| `POST /api/export-requests/{request_id}/approve` (중계) | `{}` → `{request_id, approval_id, delivery_id, expires_at}` |

정상 승인 대상 소개 JSON 키: `member_pseudo_id`, `age_band`, `job_group`, `introduction` (각 1~300자). purpose 는 `introduction`, 동의 item 은 `profile`/`photo`/`contact` (소개 자료 반출은 profile).

### 회원가입 요청·응답
`POST /api/signup` (external-api), 중계·내부 `POST /api/internal/member-signups` 본문은 같다. 모든 항목 필수(프로필 포함), 정의되지 않은 필드는 422.
```json
{"username": "영문 소문자 시작 4~20자 [a-z0-9_]", "password": "12~64자, 아이디 포함 불가 (Keycloak 에만 저장)",
 "name": "이름", "gender": "남|여", "birth_date": "YYYY-MM-DD (만 19세 이상)",
 "contact_phone": "010-1234-5678", "contact_email": "이메일",
 "education_level": "고졸|전문대졸|4년제 대졸|대학원졸", "job_group": "직군 (40자 이내)",
 "height_cm": "120~230", "weight_kg": "30~200", "introduction": "300자 이내",
 "privacy_consent": true, "consent_version": "2026-11"}
```
- 성공 201 → external `{"status": "registered"}` (회원 코드·담당자 등 내부 값은 돌려주지 않음).
- 실패: 아이디·이메일 중복 409 INVALID_STATE "이미 사용 중인 아이디 또는 이메일입니다.", 형식·나이 422 INVALID_REQUEST(사유 문구 포함), 요청 횟수 초과 409, Origin 불일치 403.

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
| `POST /api/approvals/revoke-by-label` | `{"label": "A-001_file1"}` → 중계 회수 응답 그대로. 이름 → approval_id 는 내부 `intro_files` 에서 찾음 ※명세 외 추가 |
| `GET /api/export-requests`, `/{request_id}` (내부 전달) | 중계 응답에 화면용 필드 추가: `label`, `consent_label`(C-n), `requester_pseudo_id`·`member_pseudo_id`·`recipient_pseudo_id`, 알고 있으면 `approval_id` |
| `GET /api/notifications` | 직원 전체 → `{"unread", "items": [{notification_id, kind, title, body, link_view, created_at, read}]}` (본인 알림 최근 100건) ※명세 외 추가 |
| `POST /api/notifications/read` | `{"ids": [...]}` 또는 `{"all": true}` → `{updated, unread}` (본인 알림만) |
| `POST /api/notifications/delete` | `{"ids": [...]}` 또는 `{"all": true}` → `{deleted, unread}` (본인 알림만) |
