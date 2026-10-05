FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Run as an unprivileged user; uploaded files live in a dedicated, user-owned directory.
RUN useradd --system --uid 10001 --home-dir /app scanner \
    && mkdir -p /data/storage \
    && chown -R scanner:scanner /data /app

COPY --chown=scanner:scanner alembic.ini ./
COPY --chown=scanner:scanner alembic ./alembic
COPY --chown=scanner:scanner app ./app

USER scanner
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
