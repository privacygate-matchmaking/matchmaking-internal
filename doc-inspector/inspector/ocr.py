"""로컬 OCR(Tesseract)과 이미지 처리. 외부로 아무것도 보내지 않는다.

- PDF 는 poppler(pdftoppm)로 앞 2쪽만 PNG 로 바꾼다.
- Tesseract TSV 출력에서 단어 좌표를 읽어 줄 단위로 묶는다.
- 마스킹: 대상 단어 좌표에 검은 상자를 그리고, '검토·마스킹 사본' 표시를 넣는다.
- 사진: EXIF(촬영 위치 등)를 버리고 다시 인코딩한다.
"""
import base64
import hashlib
import io
import os
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageOps

from .rules import Line, Word

Image.MAX_IMAGE_PIXELS = 40_000_000          # 압축 폭탄 방지
MAX_PAGES = 2
DPI = 200
TIMEOUT = 40
FONT_PATHS = ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
              "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc")


def font(size: int):
    for path in FONT_PATHS:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size, index=1)     # index 1 = KR
            except OSError:
                continue
    return ImageFont.load_default()


def pdf_pages(data: bytes) -> list[Image.Image]:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "in.pdf"
        src.write_bytes(data)
        subprocess.run(["pdftoppm", "-r", str(DPI), "-png", "-f", "1", "-l", str(MAX_PAGES), str(src), f"{tmp}/p"],
                       check=True, timeout=TIMEOUT, capture_output=True)
        pages = []
        for p in sorted(Path(tmp).glob("p-*.png")):
            with Image.open(p) as im:
                pages.append(im.convert("L").copy())
        if not pages:
            raise ValueError("pdf_no_pages")
        return pages


def ocr_lines(image: Image.Image) -> list[Line]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "page.png"
        image.save(path)
        out = subprocess.run(["tesseract", str(path), "stdout", "-l", "kor+eng", "--psm", "6", "-c", "tessedit_create_tsv=1"],
                             check=True, timeout=TIMEOUT, capture_output=True).stdout.decode("utf-8", "replace")
    groups: dict[tuple, Line] = {}
    for row in out.splitlines()[1:]:
        cols = row.split("\t")
        if len(cols) < 12 or cols[0] != "5" or not cols[11].strip():
            continue
        key = (int(cols[2]), int(cols[3]), int(cols[4]))           # block, par, line
        box = (int(cols[6]), int(cols[7]), int(cols[8]), int(cols[9]))
        groups.setdefault(key, Line()).words.append(Word(cols[11].strip(), box))
    return [groups[k] for k in sorted(groups, key=lambda k: (min(w.box[1] for w in groups[k].words), k))]


def masked_copy(page: Image.Image, lines: list[Line], mask: list[tuple[int, int]], kind_ko: str) -> bytes:
    im = page.convert("RGB")
    draw = ImageDraw.Draw(im)
    by_line: dict[int, list[int]] = {}
    for li, wi in mask:
        by_line.setdefault(li, []).append(wi)
    for li, idxs in by_line.items():
        words = lines[li].words
        top = min(w.box[1] for w in words) - 10                   # 줄 전체 높이로 가린다 (글자 끝 노출 방지)
        bottom = max(w.box[1] + w.box[3] for w in words) + 10
        idxs = sorted(set(idxs))
        run = [idxs[0]]
        for wi in idxs[1:] + [None]:
            if wi is not None and wi == run[-1] + 1:
                run.append(wi)
                continue
            left = words[run[0]].box[0] - 10                      # 이어진 단어는 사이 공백까지 한 상자로
            right = words[run[-1]].box[0] + words[run[-1]].box[2] + 10
            draw.rectangle([left, top, right, bottom], fill=(0, 0, 0))
            if wi is not None:
                run = [wi]
    im = im.convert("L")
    if im.width > 1000:
        im = im.resize((1000, round(im.height * 1000 / im.width)))
    band = 60
    canvas = Image.new("L", (im.width, im.height + band), 255)
    canvas.paste(im, (0, 0))
    d = ImageDraw.Draw(canvas)
    d.rectangle([0, im.height, im.width, im.height + band], fill=40)
    d.text((20, im.height + 14), f"이음 검토·마스킹 사본 · {kind_ko} · 원본 아님 · 다른 용도 사용 금지", font=font(24), fill=255)
    buf = io.BytesIO()
    canvas.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def clean_photo(data: bytes) -> tuple[bytes, dict]:
    with Image.open(io.BytesIO(data)) as im:
        if im.format not in ("JPEG", "PNG"):
            raise ValueError("photo_format")
        had_exif = bool(im.info.get("exif")) or bool(getattr(im, "getexif", lambda: {})())
        im = ImageOps.exif_transpose(im).convert("RGB")
        im.thumbnail((640, 640))
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=82, optimize=True)        # EXIF·위치 정보 없이 다시 저장
    return buf.getvalue(), {"metadata_removed": had_exif, "width": im.width, "height": im.height}


def encode(data: bytes, media_type: str) -> dict:
    return {"media_type": media_type, "sha256": hashlib.sha256(data).hexdigest(),
            "data_base64": base64.b64encode(data).decode("ascii")}
