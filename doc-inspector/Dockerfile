# 증빙 자동 검사 (로컬 OCR·규칙 탐지·마스킹). 외부 전송 없음, 비밀값·DB·저장소 접근 없음
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_THREAD_LIMIT=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-kor tesseract-ocr-eng poppler-utils fonts-noto-cjk \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY inspector ./inspector

RUN useradd --system --uid 10002 inspector
USER inspector
EXPOSE 8000
CMD ["uvicorn", "inspector.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
