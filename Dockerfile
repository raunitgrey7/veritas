# Multi-stage build. The builder resolves dependencies with uv into a virtual
# environment; the runtime stage copies only that environment and the source, and
# runs as a non-root user. The base path stays deterministic and offline: no model
# weights, no network calls at runtime.

FROM python:3.13-slim AS builder

# Install uv from its official image (pinned minor) without extra tooling.
COPY --from=ghcr.io/astral-sh/uv:0.13 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Resolve dependencies first so the layer caches when only source changes.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev

# Add the source and install the project itself.
COPY src ./src
RUN uv sync --frozen --no-dev


FROM python:3.13-slim AS runtime

# Create an unprivileged user to run the service.
RUN useradd --create-home --uid 10001 veritas

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=builder --chown=veritas:veritas /app/.venv /app/.venv
COPY --chown=veritas:veritas src ./src
COPY --chown=veritas:veritas pyproject.toml README.md ./

USER veritas

EXPOSE 8000

# Container healthcheck hits the liveness endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

CMD ["uvicorn", "veritas.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
