FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

ARG GIT_COMMIT=unknown
LABEL org.opencontainers.image.source="https://github.com/ShreyanshVaibhaw/Leaflyst" \
      org.opencontainers.image.revision="$GIT_COMMIT"

COPY --from=ghcr.io/astral-sh/uv:0.11.24@sha256:99ea34acedc870ba4ad11a1f540a1c04267c9f30aadc465a94406f52dfda2c36 /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY apps/api apps/api
COPY packages/schemas packages/schemas
COPY packages/abx-sdk packages/abx-sdk
COPY packages/abx-tap packages/abx-tap
COPY services/scanner services/scanner
COPY services/rules services/rules
COPY infra/migrate.py infra/migrate.py
COPY infra/postgres infra/postgres

RUN uv sync --frozen --no-dev --package abx-api \
    && groupadd --gid 10001 abx \
    && useradd --uid 10001 --gid abx --no-create-home --shell /usr/sbin/nologin abx

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

CMD ["uvicorn", "abx_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
