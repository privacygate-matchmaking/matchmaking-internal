# matchmaking-internal

PrivacyGate — 내부·외부 공격에 대응하는 개인정보 접근·반출 통제 시스템 (가상 결혼정보회사)
의 **내부 영역**: 직원 화면(internal-web), 업무 API(internal-api).
실행 환경(compose)·DB 스키마·infra 는 `privacygate` 레포에 있다.

```
matchmaking-internal/
├─ internal-web/           Nginx + HTML/JS
├─ internal-api/           FastAPI (+ privacygate 패키지)
├─ tests/
└─ docs/                   architecture.md, api-spec.md, permissions.md
```

## 실행

세 레포를 **같은 상위 폴더**에 나란히 둔다.

```bash
git clone https://github.com/privacygate-matchmaking/matchmaking-internal.git
git clone https://github.com/privacygate-matchmaking/matchmaking-external.git   # 외부 담당 레포 (없어도 내부는 실행됨)
git clone https://github.com/privacygate-matchmaking/privacygate.git
cd privacygate
./infra/scripts/init-env.sh          # .env, infra/secrets/evidence_master.key 생성
docker compose up -d --build                     # 내부만 (keycloak, internal-web, internal-api, business-db)
# docker compose --profile external up -d --build  # 외부·중계까지 (../matchmaking-external 필요)
```

| 주소 | 용도 |
| --- | --- |
| https://localhost:8080 | 직원 화면 |
| https://localhost:8081 | Keycloak (관리 콘솔 `/admin`, 계정 infra_admin) |
| https://localhost:8090 | 회원 화면 |

HTTPS 인증서는 `init-env.sh` 가 만든다. [mkcert](https://github.com/FiloSottile/mkcert) 가 설치돼 있으면(`mkcert -install` 한 번) 브라우저 경고가 없고, 없으면 자체 서명이라 처음 한 번 '계속 진행'이 필요하다.

시험 계정 `counselor_a`, `data_admin`, `approver`, `member_b` — 비밀번호는 `.env` 의 `KC_TEST_PASSWORD`. 직원은 첫 로그인 때 OTP 앱 등록.

## 시험

```bash
python3 -m unittest discover -s tests        # 경로 권한 선언 (fastapi 없으면 건너뜀)
```

## 주의

- 비밀값(`.env`, `infra/secrets/`)은 privacygate 레포에서만 생기며 커밋하지 않는다. 커밋 전 `git status` 확인.
- 모든 회원 데이터는 합성 데이터다. 실제 개인정보·키·비밀번호·세션 값을 AI 도구에 넣지 않는다.
