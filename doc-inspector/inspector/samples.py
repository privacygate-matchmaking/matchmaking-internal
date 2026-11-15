"""합성 증빙 PDF·사진 만들기 (시험용). 실제 기관 양식·로고를 흉내 내지 않는 '이음 시험용' 문서다.

발급번호는 회원 코드 번호와 문서 종류로 정해지며, 업무 DB 의 합성 발급대장(doc_registry)과 맞는다.
  python -m inspector.samples --out /out --code A-003 --name 박도윤 --birth 1992-03-14 \
      --income 52000000 --marital 미혼 --property 서울특별시
"""
import argparse
import io
from pathlib import Path

from PIL import Image, ImageDraw

from .ocr import font
from .rules import make_issue_no

KIND_INDEX = {"identity": 1, "marital": 2, "income": 3, "property": 4, "education": 5, "employment": 6}
TITLES = {"identity": "신분 확인서 (이음 시험용)", "marital": "혼인관계 확인서 (이음 시험용)",
          "income": "소득금액 확인서 (이음 시험용)", "property": "부동산 보유 확인서 (이음 시험용)",
          "education": "졸업 확인서 (이음 시험용)", "employment": "재직 확인서 (이음 시험용)"}


def issue_no(code: str, kind: str) -> str:
    """A-003 + income → 2026-000033-x (회원 번호 * 10 + 종류)."""
    number = int(code.split("-")[1])
    letter = ord(code[0]) - ord("A")
    return make_issue_no(2026, letter * 10000 + number * 10 + KIND_INDEX[kind])


def rrn(birth: str, gender: str) -> str:
    y, m, d = birth.split("-")
    g = ("1" if gender == "남" else "2") if y.startswith("19") else ("3" if gender == "남" else "4")
    return f"{y[2:]}{m}{d}-{g}000000"            # 뒷자리는 합성 값


def page(lines: list[str], title: str) -> bytes:
    im = Image.new("L", (1240, 1754), 255)
    d = ImageDraw.Draw(im)
    d.text((120, 100), title, font=font(48), fill=0)
    d.line([120, 180, 1120, 180], fill=0, width=3)
    y = 240
    for text in lines:
        d.text((120, y), text, font=font(34), fill=0)
        y += 78
    d.text((120, 1600), "※ 학교 프로젝트용 합성 문서입니다. 실제 증명서가 아닙니다.", font=font(26), fill=80)
    buf = io.BytesIO()
    im.save(buf, "PDF", resolution=150)
    return buf.getvalue()


def documents(a) -> dict[str, bytes]:
    base = [f"성명: {a.name}", f"주민등록번호: {rrn(a.birth, a.gender)}"]
    docs = {
        "identity": base + [f"주소: {a.address}", f"발급번호: {issue_no(a.code, 'identity')}"],
        "marital": base + [f"등록기준지: {a.address}", f"혼인상태: {a.marital}",
                           "배우자: 해당 없음" if a.marital == "미혼" else "배우자: 홍길동",
                           f"발급번호: {issue_no(a.code, 'marital')}"],
        "income": base + [f"주소: {a.address}", f"회사명: {a.company}", f"연간 총소득: {a.income:,}원",
                          f"발급번호: {issue_no(a.code, 'income')}"],
        "property": base + ([f"소재지: {a.property} 중앙로 100, 101동 1001호", "공시가격: 450,000,000원"]
                            if a.property != "none" else ["보유 부동산: 없음"]) + [f"발급번호: {issue_no(a.code, 'property')}"],
        "education": base + [f"학교명: {a.school}", "학위: 학사", "졸업일: 2016-02-20", f"발급번호: {issue_no(a.code, 'education')}"],
        "employment": base + [f"회사명: {a.company}", "직위: 대리", "재직기간: 2019-03-02 ~ 현재", f"연락처: 010-1234-5678",
                              f"발급번호: {issue_no(a.code, 'employment')}"],
    }
    return {k: page(v, TITLES[k]) for k, v in docs.items()}


def photo() -> bytes:
    """사람 얼굴이 아닌 추상 도형 이미지 + 가짜 촬영 위치 EXIF (메타데이터 제거 확인용)."""
    im = Image.new("RGB", (900, 900), (236, 228, 214))
    d = ImageDraw.Draw(im)
    d.ellipse([300, 180, 600, 480], fill=(120, 140, 160))
    d.rounded_rectangle([220, 520, 680, 860], radius=120, fill=(120, 140, 160))
    exif = Image.Exif()
    exif[0x010F] = "IEUM-TEST-CAMERA"        # Make
    exif[0x0132] = "2026:11:01 10:00:00"     # DateTime
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=90, exif=exif)
    return buf.getvalue()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--code", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--birth", required=True)
    p.add_argument("--gender", default="남", choices=["남", "여"])
    p.add_argument("--address", default="서울특별시 마포구 월드컵로 12")
    p.add_argument("--company", default="이음테크")
    p.add_argument("--school", default="이음대학교")
    p.add_argument("--income", type=int, default=52_000_000)
    p.add_argument("--marital", default="미혼", choices=["미혼", "이혼", "사별"])
    p.add_argument("--property", default="서울특별시", help="시·도 이름 또는 none")
    a = p.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for kind, data in documents(a).items():
        (out / f"{a.code}_{kind}.pdf").write_bytes(data)
    (out / f"{a.code}_photo.jpg").write_bytes(photo())
    print(f"{a.code}: 합성 증빙 6종 + 사진 → {out}")


if __name__ == "__main__":
    main()
