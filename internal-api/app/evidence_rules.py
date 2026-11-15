"""증빙 종류와 공개 가능한 사실의 허용 값 (doc-inspector rules 와 같은 기준).

다른 회원에게 갈 수 있는 것은 아래 요약(구간·여부)과 마스킹 사본뿐이다. 금액·주소·발급번호 원값은 공개하지 않는다.
"""
KINDS = ("education", "employment", "identity", "marital", "income", "property", "photo")
KIND_KO = {"education": "학력", "employment": "재직", "identity": "신분증", "marital": "혼인관계",
           "income": "소득", "property": "부동산", "photo": "프로필 사진"}
PDF_KINDS = ("education", "employment", "identity", "marital", "income", "property")
# 사본(마스킹 이미지)을 다른 회원에게 줄 수 있는 문서 (신분증은 절대 불가)
DOCUMENT_KINDS = ("education", "employment", "income", "marital", "property")
INCOME_BANDS = ("3천만원 미만", "3천만~5천만원", "5천만~7천만원", "7천만~1억원", "1억원 이상")
MARITAL = ("미혼", "이혼", "사별")
REGIONS = ("서울특별시", "부산광역시", "대구광역시", "인천광역시", "광주광역시", "대전광역시", "울산광역시",
           "세종특별자치시", "경기도", "강원특별자치도", "충청북도", "충청남도", "전북특별자치도", "전라남도",
           "경상북도", "경상남도", "제주특별자치도")
# 공개 범위(scope) → 증빙 종류
SCOPE_KIND = {"profile": "education", "education": "education", "employment": "employment", "income": "income",
              "marital_status": "marital", "property": "property", "photo": "photo"}
TEXT_SCOPES = ("profile", "education", "employment", "income", "marital_status", "property")
# 화면 열람 없이 승인 자료(반출)로만 제공하는 범위
RELEASE_ONLY_SCOPES = ("photo", "documents")          # 직원 요청 + 승인자 승인 후 상대 화면에 자동 표시
CONDITIONAL_SCOPES = ("name", "contact")              # 이름: 동의만, 연락처: 일정 확정 + 상호 동의 (중계 확인)
ALL_SCOPES = TEXT_SCOPES + RELEASE_ONLY_SCOPES + CONDITIONAL_SCOPES


def validate_facts(kind: str, facts: dict | None) -> dict:
    facts = facts or {}
    if kind == "marital":
        if facts.get("status") not in MARITAL:
            raise ValueError("혼인 상태를 선택하세요 (미혼·이혼·사별).")
        return {"status": facts["status"]}
    if kind == "income":
        if facts.get("band") not in INCOME_BANDS:
            raise ValueError("연소득 구간을 선택하세요.")
        return {"band": facts["band"]}
    if kind == "property":
        if facts.get("owns") is True:
            if facts.get("region") not in REGIONS:
                raise ValueError("부동산 소재 시·도를 선택하세요.")
            return {"owns": True, "region": facts["region"]}
        if facts.get("owns") is False:
            return {"owns": False}
        raise ValueError("부동산 보유 여부를 선택하세요.")
    return {}


def summary(kind: str, facts: dict) -> str:
    if kind == "marital":
        return f"혼인관계 확인: {facts['status']}"
    if kind == "income":
        return f"연소득 구간: {facts['band']} (소득 증빙 확인)"
    if kind == "property":
        return f"부동산: 보유 ({facts['region']})" if facts.get("owns") else "부동산: 보유 내역 없음 확인"
    return {"identity": "본인 확인 완료", "photo": "프로필 사진 검토 완료 (위치 등 메타데이터 제거)",
            "education": "학력 증빙 검토 완료", "employment": "재직 증빙 검토 완료"}[kind]
