"""증빙 문서 규칙: 개인정보 탐지, 마스킹 대상 선택, 공개용 사실 추출, 발급번호 형식 검사.

OCR 결과(줄·단어·좌표)만 입력으로 받는 순수 함수라 OCR 없이도 시험할 수 있다.
탐지 결과에는 개인정보 값 자체를 넣지 않고 종류별 건수만 담는다 (fields 는 직원 심사 화면 전용).
"""
import re
from dataclasses import dataclass, field

KINDS = ("identity", "marital", "income", "property", "education", "employment", "photo")
KIND_KO = {"identity": "신분증", "marital": "혼인관계증명서", "income": "소득 증빙", "property": "부동산 증빙",
           "education": "학력 증빙", "employment": "재직 증빙", "photo": "프로필 사진"}

# 공개 구간 (금액 원값은 공개하지 않는다)
INCOME_BANDS = ("3천만원 미만", "3천만~5천만원", "5천만~7천만원", "7천만~1억원", "1억원 이상")
MARITAL = ("미혼", "이혼", "사별")
REGIONS = ("서울특별시", "부산광역시", "대구광역시", "인천광역시", "광주광역시", "대전광역시", "울산광역시",
           "세종특별자치시", "경기도", "강원특별자치도", "충청북도", "충청남도", "전북특별자치도", "전라남도",
           "경상북도", "경상남도", "제주특별자치도")
_REGION_SHORT = {"서울": "서울특별시", "부산": "부산광역시", "대구": "대구광역시", "인천": "인천광역시",
                 "광주": "광주광역시", "대전": "대전광역시", "울산": "울산광역시", "세종": "세종특별자치시",
                 "경기": "경기도", "강원": "강원특별자치도", "충북": "충청북도", "충남": "충청남도",
                 "전북": "전북특별자치도", "전남": "전라남도", "경북": "경상북도", "경남": "경상남도", "제주": "제주특별자치도"}

PATTERNS = {
    "resident_number": re.compile(r"\d{6}\s*-\s*[1-4]\d{6}"),
    "phone": re.compile(r"01[016789]\s*-?\s*\d{3,4}\s*-?\s*\d{4}"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "account_number": re.compile(r"\b\d{3,6}-\d{2,6}-\d{2,8}\b"),
}
_DATE = re.compile(r"(19|20)\d{2}-\d{2}-\d{2}")
ISSUE_RE = re.compile(r"(20\d{2})\s*-\s*(\d{6})\s*-\s*(\d)")

# 값 부분을 가릴 항목 이름 (문서 종류별). 이름 뒤 ':' 이후 단어를 가린다.
_COMMON = ("성명", "이름", "주민등록번호", "생년월일", "주소", "연락처", "전화", "휴대전화", "이메일", "발급번호", "등록기준지")
MASK_LABELS = {
    "identity": _COMMON,
    "marital": _COMMON + ("배우자", "부", "모", "본인"),
    "income": _COMMON + ("회사명", "사업장", "사업자등록번호", "연간 총소득", "총소득", "소득금액", "결정세액"),
    "property": _COMMON + ("소유자", "소재지", "지번", "공시가격", "과세표준", "재산세"),
    "education": _COMMON + ("학교명", "학번"),
    "employment": _COMMON + ("회사명", "사업자등록번호", "사번", "부서"),
    "photo": (),
}
LABEL_TYPE = {"주소": "address", "소재지": "address", "등록기준지": "address", "지번": "address",
              "성명": "name", "이름": "name", "소유자": "name", "배우자": "name", "부": "name", "모": "name", "본인": "name"}


@dataclass
class Word:
    text: str
    box: tuple[int, int, int, int]      # left, top, width, height (픽셀)


@dataclass
class Line:
    words: list[Word] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ".join(w.text for w in self.words)


def _squash(text: str) -> str:
    return re.sub(r"\s+", "", text)


def luhn_digit(digits: str) -> int:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch) * (2 if i % 2 == 0 else 1)
        total += n - 9 if n > 9 else n
    return (10 - total % 10) % 10


def make_issue_no(year: int, serial: int) -> str:
    body = f"{year:04d}{serial:06d}"
    return f"{year:04d}-{serial:06d}-{luhn_digit(body)}"


def parse_issue(text: str) -> dict:
    m = ISSUE_RE.search(text)
    if not m:
        return {"number": None, "format_ok": False, "checksum_ok": False}
    year, serial, check = m.groups()
    return {"number": f"{year}-{serial}-{check}", "format_ok": True,
            "checksum_ok": luhn_digit(year + serial) == int(check)}


def _label_of(line: Line, labels) -> tuple[str | None, int]:
    """줄 머리의 항목 이름과, 값이 시작하는 단어 위치."""
    joined = ""
    for idx, w in enumerate(line.words):
        joined += w.text
        head = joined.split(":")[0] if ":" in joined else None
        if head is not None:
            head = _squash(head)
            for label in sorted(labels, key=len, reverse=True):
                if head == _squash(label):
                    # ':' 가 단어 중간에 붙어 있으면(성명:박도윤) 그 단어도 값으로 본다
                    tail = w.text.split(":", 1)[1] if ":" in w.text else ""
                    return label, idx if tail.strip() else idx + 1
            return None, 0
        if len(joined) > 20:
            break
    return None, 0


def _value_text(line: Line) -> str:
    text = line.text
    return text.split(":", 1)[1].strip() if ":" in text else ""


def _match_words(line: Line, pattern: re.Pattern) -> list[int]:
    """정규식이 걸린 글자 범위와 겹치는 단어 위치."""
    spans, pos, text = [], 0, ""
    for w in line.words:
        if text:
            text += " "
            pos += 1
        spans.append((pos, pos + len(w.text)))
        text += w.text
        pos += len(w.text)
    hits = set()
    for m in pattern.finditer(text):
        if pattern is PATTERNS["account_number"]:
            raw = m.group()
            if (_DATE.fullmatch(raw) or ISSUE_RE.fullmatch(raw) or PATTERNS["phone"].fullmatch(raw)
                    or len(re.sub(r"\D", "", raw)) < 10):
                continue
        for i, (a, b) in enumerate(spans):
            if a < m.end() and m.start() < b:
                hits.add(i)
    return sorted(hits)


def birth_from_rrn(text: str) -> str | None:
    m = PATTERNS["resident_number"].search(text)
    if not m:
        return None
    digits = re.sub(r"\D", "", m.group())
    yy, mm, dd, g = digits[0:2], digits[2:4], digits[4:6], digits[6]
    century = "19" if g in "12" else "20"
    return f"{century}{yy}-{mm}-{dd}"


def income_band(amount: int) -> str:
    if amount < 30_000_000:
        return INCOME_BANDS[0]
    if amount < 50_000_000:
        return INCOME_BANDS[1]
    if amount < 70_000_000:
        return INCOME_BANDS[2]
    if amount < 100_000_000:
        return INCOME_BANDS[3]
    return INCOME_BANDS[4]


def region_of(text: str) -> str | None:
    squashed = _squash(text)
    for r in REGIONS:
        if r in squashed:
            return r
    for short, full in _REGION_SHORT.items():
        if squashed.startswith(short):
            return full
    return None


def summary(kind: str, facts: dict) -> str:
    """다른 회원에게 공개될 수 있는 한 줄 (원값 없이 구간·여부만)."""
    if kind == "marital":
        return f"혼인관계 확인: {facts['status']}"
    if kind == "income":
        return f"연소득 구간: {facts['band']} (소득 증빙 확인)"
    if kind == "property":
        return f"부동산: 보유 ({facts['region']})" if facts.get("owns") else "부동산: 보유 내역 없음 확인"
    if kind == "identity":
        return "본인 확인 완료"
    if kind == "photo":
        return "프로필 사진 검토 완료"
    if kind == "education":
        return "학력 증빙 검토 완료"
    if kind == "employment":
        return "재직 증빙 검토 완료"
    raise ValueError(kind)


def validate_facts(kind: str, facts: dict) -> dict:
    """직원이 확정한 공개 사실 검사 (허용 값만)."""
    facts = facts or {}
    if kind == "marital":
        if facts.get("status") not in MARITAL:
            raise ValueError("marital_status_invalid")
        return {"status": facts["status"]}
    if kind == "income":
        if facts.get("band") not in INCOME_BANDS:
            raise ValueError("income_band_invalid")
        return {"band": facts["band"]}
    if kind == "property":
        if facts.get("owns") is True:
            if facts.get("region") not in REGIONS:
                raise ValueError("property_region_invalid")
            return {"owns": True, "region": facts["region"]}
        if facts.get("owns") is False:
            return {"owns": False}
        raise ValueError("property_owns_invalid")
    return {}


def analyze(lines: list[Line], kind: str) -> dict:
    """탐지·마스킹 대상·추출 값·제안 사실을 만든다."""
    if kind not in KINDS:
        raise ValueError("unknown_kind")
    labels = MASK_LABELS[kind]
    detected: dict[str, int] = {}
    mask: list[tuple[int, int]] = []          # (줄, 단어)
    fields: dict[str, str] = {}
    full = "\n".join(l.text for l in lines)

    for li, line in enumerate(lines):
        label, start = _label_of(line, labels)
        if label:
            for wi in range(start, len(line.words)):
                mask.append((li, wi))
            t = LABEL_TYPE.get(label)
            if t:
                detected[t] = detected.get(t, 0) + 1
            fields.setdefault(label, _value_text(line))
        for name, pattern in PATTERNS.items():
            hits = _match_words(line, pattern)
            if hits:
                detected[name] = detected.get(name, 0) + 1
                mask.extend((li, wi) for wi in hits)
        if _match_words(line, ISSUE_RE):
            mask.extend((li, wi) for wi in _match_words(line, ISSUE_RE))

    issue = parse_issue(full)
    name = fields.get("성명") or fields.get("이름") or fields.get("본인")
    extracted = {"name": _squash(name) if name else None,
                 "birth": birth_from_rrn(full) or (re.search(r"(19|20)\d{2}-\d{2}-\d{2}", fields.get("생년월일", "")) or [None])[0]}
    proposed: dict = {}
    if kind == "marital":
        text = fields.get("혼인상태", "") or full
        for status in MARITAL:
            if status in _squash(text):
                proposed = {"status": status}
                break
        if not proposed and re.search(r"혼인\s*사항\s*:\s*(해당\s*없음|없음)", full):
            proposed = {"status": "미혼"}
    elif kind == "income":
        for label in ("연간 총소득", "총소득", "소득금액"):
            raw = fields.get(label)
            if raw:
                digits = re.sub(r"[^\d]", "", raw.split("원")[0])
                if digits:
                    extracted["amount"] = int(digits)
                    proposed = {"band": income_band(int(digits))}
                    break
    elif kind == "property":
        if re.search(r"보유\s*부동산\s*:\s*(없음|해당\s*없음)", full):
            proposed = {"owns": False}
        else:
            region = region_of(fields.get("소재지", ""))
            if region:
                proposed = {"owns": True, "region": region}
    elif kind == "education":
        for degree in ("박사", "석사", "학사", "전문학사", "고등학교"):
            if degree in full:
                extracted["degree"] = degree
                break
    elif kind == "employment":
        extracted["employed"] = "재직" in full

    try:
        proposed_summary = summary(kind, validate_facts(kind, proposed)) if proposed or kind not in ("marital", "income", "property") else None
    except ValueError:
        proposed_summary = None
    return {"detected": detected, "mask": sorted(set(mask)), "issue": issue,
            "extracted": {k: v for k, v in extracted.items() if v is not None},
            "proposed": proposed, "summary": proposed_summary}
