FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY requirements.txt ./
COPY app.py config.py shared_http.py shared_docs.py setup_tokens.py HOWTO.md ./
COPY templates ./templates
RUN pip install --no-cache-dir -r requirements.txt

RUN chown -R appuser:appuser /app

RUN chgrp -R 0 /app && chmod -R g=u /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ['PORT'] + '/health', timeout=3)" || exit 1

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --timeout 60 app:app"]
