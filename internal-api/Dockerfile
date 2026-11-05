FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 공통 보안 모듈: compose 의 additional_contexts(privacygate 레포)에서 패키지 파일만 복사
# (.env·infra/secrets 가 이미지에 들어가지 않도록 폴더 전체를 복사하지 않는다)
COPY --from=privacygate pyproject.toml README.md /opt/privacygate/
COPY --from=privacygate src /opt/privacygate/src
RUN pip install --no-cache-dir "/opt/privacygate[web]"

COPY app ./app

RUN useradd --system --uid 10001 app \
 && mkdir -p /var/log/matchmaking /data/evidence-storage \
 && chown app /var/log/matchmaking /data/evidence-storage
USER app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
