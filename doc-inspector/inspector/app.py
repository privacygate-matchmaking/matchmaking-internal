"""doc-inspector: 증빙 자동 검사 서비스 (internal-api 전용).

격리 원칙
- internal-api 와만 연결된 내부망(inspect-net)에 둔다. 인터넷·DB·키·저장소에 접근하지 않는다.
- 받은 파일은 메모리·임시 폴더에서만 처리하고 남기지 않는다 (읽기 전용 파일시스템 + tmpfs).
- 응답에 OCR 원문 전체를 넣지 않는다. 직원 확인용 추출 값(fields)과 종류별 탐지 건수만 돌려준다.
"""
import logging

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from . import ocr, rules

VERSION = "doc-inspector/1.0 (tesseract kor+eng, rule-based)"
MAX_BYTES = 2 * 1024 * 1024
log = logging.getLogger("doc-inspector")
app = FastAPI(title="doc-inspector", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def health():
    return {"ok": True, "version": VERSION}


@app.post("/inspect")
async def inspect(file: UploadFile = File(...), kind: str = Form(...)):
    if kind not in rules.KINDS:
        raise HTTPException(400, "unknown_kind")
    data = await file.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        raise HTTPException(400, "file_size")
    try:
        if kind == "photo":
            if not (data.startswith(b"\xff\xd8\xff") or data.startswith(b"\x89PNG\r\n\x1a\n")):
                raise ValueError("photo_format")
            cleaned, meta = ocr.clean_photo(data)
            return {"kind": kind, "version": VERSION, "pages": 1, "ocr_chars": 0, "detected": {},
                    "masked_words": 0, "issue": {"number": None, "format_ok": False, "checksum_ok": False},
                    "fields": {}, "proposed": {}, "summary": rules.summary("photo", {}), "photo": meta,
                    "masked": ocr.encode(cleaned, "image/jpeg")}
        if not data.startswith(b"%PDF-"):
            raise ValueError("not_pdf")
        pages = ocr.pdf_pages(data)
        lines = ocr.ocr_lines(pages[0])
        if len(pages) > 1:          # 2쪽은 탐지에만 쓴다 (사본은 1쪽)
            extra = ocr.ocr_lines(pages[1])
        else:
            extra = []
        result = rules.analyze(lines, kind)
        extra_result = rules.analyze(extra, kind) if extra else {"detected": {}}
        for k, v in extra_result["detected"].items():
            result["detected"][k] = result["detected"].get(k, 0) + v
        masked = ocr.masked_copy(pages[0], lines, result["mask"], rules.KIND_KO[kind])
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except Exception:
        log.exception("inspection failed")
        raise HTTPException(500, "inspection_failed") from None
    return {"kind": kind, "version": VERSION, "pages": len(pages),
            "ocr_chars": sum(len(l.text) for l in lines + extra),
            "detected": result["detected"], "masked_words": len(result["mask"]),
            "issue": result["issue"], "fields": result["extracted"], "proposed": result["proposed"],
            "summary": result["summary"], "masked": ocr.encode(masked, "image/png")}
