FROM python:3.12-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

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
    && rm /bin/uv /bin/uvx \
    && groupadd --gid 10001 abx \
    && useradd --uid 10001 --gid abx --no-create-home --shell /usr/sbin/nologin abx \
    && dpkg --purge --force-remove-essential perl-base \
    && find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod ug-s {} +

# perl-base is Debian-Essential but nothing in this runtime interprets Perl: the
# image runs uvicorn, the workers, and infra/migrate.py, and no package is
# installed after this line. Debian ships no fix for its four open criticals, so
# purging is the only way to reach the zero-critical release gate. Removing it
# after the last apt/dpkg call keeps maintainer scripts intact during the build.
#
# The setuid strip matters more than it looks. The image shipped su, mount,
# passwd, and eight others owned by root with the setuid bit, all reachable by
# uid 10001. The open util-linux advisory is only accepted as low risk because
# nothing here can escalate through those binaries, and this is the line that
# makes that true rather than assumed.

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

CMD ["uvicorn", "abx_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
