# ---- build stage: resolve the locked environment with uv -------------------
# Plain COPY+RUN layering (no BuildKit-only mounts) on purpose: the image
# builds identically under BuildKit and the classic builder.
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

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
FROM python:3.13-slim AS runtime

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
