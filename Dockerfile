# ---- build stage: resolve the locked environment with uv -------------------
# Plain COPY+RUN layering on purpose: the image builds identically under
# BuildKit and the classic builder — no RUN --mount, heredocs, COPY --link
# or FROM --platform=. CI and release build with DOCKER_BUILDKIT=0 to keep
# it that way.
FROM ghcr.io/astral-sh/uv:python3.13-trixie-slim AS builder

# bytecode for faster cold starts; never download a uv-managed interpreter —
# the venv must reference the same /usr/local python the runtime image has
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# dependency layer: cached until uv.lock/pyproject.toml change
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# project layer: --no-editable installs vt_proxy INTO the venv,
# so the runtime image needs nothing but the venv
COPY README.md LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# ---- runtime stage ---------------------------------------------------------
# Debian release pinned and matched to the builder's: an unpinned tag would
# follow the next Debian stable and pull the two stages apart.
FROM python:3.13-slim-trixie AS runtime

# baked in, so every build carries them, not just releases; .source is what
# links the ghcr package to this repo
LABEL org.opencontainers.image.source="https://github.com/janwychowaniak/vt-proxy" \
      org.opencontainers.image.description="Read-only VirusTotal API v3 reputation proxy" \
      org.opencontainers.image.licenses="MIT"

RUN useradd --create-home --uid 10001 app

WORKDIR /app
COPY --from=builder --chown=app:app /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

USER app
EXPOSE 8000

# static endpoint, no VT quota spent (SPEC §4)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/v1/health', timeout=4)"]

# 0.0.0.0 is container-internal only; the localhost-only guarantee lives in
# the compose port mapping 127.0.0.1:...:8000 (SPEC §2). Access log off:
# the app emits its own JSON request lines (SPEC §11).
CMD ["uvicorn", "--factory", "vt_proxy.main:create_app", \
     "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
