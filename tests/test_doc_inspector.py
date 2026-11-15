"""doc-inspector 검사 (규칙 + 실제 OCR).

실행 (privacygate 폴더에서):
  docker compose exec -T doc-inspector python - < ../matchmaking-internal/tests/test_doc_inspector.py
로컬에서는 matchmaking-internal/doc-inspector 를 PYTHONPATH 에 두고 실행 (tesseract kor 없으면 OCR 시험은 건너뜀).
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.getcwd())
for candidate in (os.path.join(os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else "", "..", "doc-inspector"),):
    if os.path.isdir(candidate):
        sys.path.insert(0, candidate)

from inspector import rules  # noqa: E402

try:
    langs = subprocess.run(["tesseract", "--list-langs"], capture_output=True, text=True, timeout=10).stdout
    HAS_OCR = "kor" in langs and shutil.which("pdftoppm") is not None
except (OSError, subprocess.SubprocessError):
    HAS_OCR = False


def line(*words):
    x, out = 0, []
    for w in words:
        out.append(rules.Word(w, (x, 0, 10 * len(w), 20)))
        x += 10 * len(w) + 10
    return rules.Line(out)


class Rules(unittest.TestCase):
    def test_issue_number_checksum(self):
        good = rules.make_issue_no(2026, 33)
        self.assertEqual(good, "2026-000033-4")
        self.assertTrue(rules.parse_issue(f"발급번호: {good}")["checksum_ok"])
        self.assertFalse(rules.parse_issue("발급번호: 2026-000033-5")["checksum_ok"])     # 위조(숫자 변경)
        self.assertFalse(rules.parse_issue("발급번호 없음")["format_ok"])

    def test_personal_data_masked_and_counted_without_values(self):
        lines = [line("성명:", "박도윤"), line("주민등록번호:", "920314-1000000"), line("주소:", "서울특별시", "마포구"),
                 line("연간", "총소득:", "52,000,000원"), line("발급번호:", "2026-000033-4"), line("직위:", "대리")]
        r = rules.analyze(lines, "income")
        self.assertEqual(r["detected"]["resident_number"], 1)
        self.assertNotIn("박도윤", str(r["detected"]))                     # 건수만, 값 없음
        masked = {(li, wi) for li, wi in r["mask"]}
        self.assertIn((0, 1), masked)          # 이름 값
        self.assertIn((1, 1), masked)          # 주민번호
        self.assertIn((3, 2), masked)          # 금액
        self.assertIn((4, 1), masked)          # 발급번호
        self.assertNotIn((5, 1), masked)       # 직위는 가리지 않음
        self.assertEqual(r["proposed"], {"band": "5천만~7천만원"})
        self.assertEqual(r["summary"], "연소득 구간: 5천만~7천만원 (소득 증빙 확인)")
        self.assertNotIn("52", r["summary"])   # 원금액은 요약에 없음

    def test_dates_are_not_account_numbers(self):
        r = rules.analyze([line("졸업일:", "2016-02-20"), line("연락처:", "010-1234-5678")], "education")
        self.assertNotIn("account_number", r["detected"])
        self.assertEqual(r["detected"].get("phone"), 1)

    def test_property_and_marital_proposals(self):
        self.assertEqual(rules.analyze([line("소재지:", "경기도", "성남시")], "property")["proposed"],
                         {"owns": True, "region": "경기도"})
        self.assertEqual(rules.analyze([line("보유", "부동산:", "없음")], "property")["proposed"], {"owns": False})
        self.assertEqual(rules.analyze([line("혼인상태:", "이혼")], "marital")["proposed"], {"status": "이혼"})

    def test_only_allowed_public_facts(self):
        with self.assertRaises(ValueError):
            rules.validate_facts("income", {"band": "52,000,000원"})
        with self.assertRaises(ValueError):
            rules.validate_facts("property", {"owns": True, "region": "서울 마포구 월드컵로 12"})
        self.assertEqual(rules.validate_facts("marital", {"status": "미혼", "spouse": "x"}), {"status": "미혼"})


@unittest.skipUnless(HAS_OCR, "tesseract(kor)·poppler 필요 (doc-inspector 컨테이너에서 실행)")
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from inspector import ocr, samples
        cls.ocr, cls.samples = ocr, samples
        cls.tmp = tempfile.mkdtemp()
        sys.argv = ["samples", "--out", cls.tmp, "--code", "A-003", "--name", "박도윤", "--birth", "1992-03-14"]
        samples.main()

    def inspect(self, kind):
        with open(os.path.join(self.tmp, f"A-003_{kind}.pdf"), "rb") as f:
            data = f.read()
        pages = self.ocr.pdf_pages(data)
        lines = self.ocr.ocr_lines(pages[0])
        return lines, rules.analyze(lines, kind), pages

    def test_income_document(self):
        lines, r, pages = self.inspect("income")
        self.assertEqual(r["issue"]["number"], self.samples.issue_no("A-003", "income"))
        self.assertTrue(r["issue"]["checksum_ok"])
        self.assertEqual(r["extracted"].get("name"), "박도윤")
        self.assertEqual(r["extracted"].get("birth"), "1992-03-14")
        self.assertEqual(r["proposed"], {"band": "5천만~7천만원"})
        png = self.ocr.masked_copy(pages[0], lines, r["mask"], "소득 증빙")
        self.assertTrue(png.startswith(b"\x89PNG"))
        # 마스킹 사본을 다시 OCR 해도 주민번호·금액이 나오지 않아야 한다
        from PIL import Image
        again = self.ocr.ocr_lines(Image.open(io.BytesIO(png)).convert("L"))
        text = " ".join(l.text for l in again)
        self.assertNotIn("920314", text)
        self.assertNotIn("52,000,000", text)
        self.assertNotRegex(text, r"2026-0000\d{2}-\d")

    def test_property_and_marital(self):
        self.assertEqual(self.inspect("property")[1]["proposed"], {"owns": True, "region": "서울특별시"})
        self.assertEqual(self.inspect("marital")[1]["proposed"], {"status": "미혼"})

    def test_photo_metadata_removed(self):
        with open(os.path.join(self.tmp, "A-003_photo.jpg"), "rb") as f:
            data = f.read()
        out, meta = self.ocr.clean_photo(data)
        from PIL import Image
        self.assertTrue(meta["metadata_removed"])
        self.assertFalse(Image.open(io.BytesIO(out)).getexif())


if __name__ == "__main__":
    unittest.main(argv=["test_doc_inspector"], verbosity=2)
