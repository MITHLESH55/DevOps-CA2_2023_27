# ============================================================
# STAGE 1 — BUILD PYTHON DEPENDENCIES
# ============================================================

FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .

RUN python -m pip install \
    --no-cache-dir \
    --no-compile \
    --prefix=/install \
    -r requirements.txt


# ============================================================
# STAGE 2 — MINIMAL AND PATCHED RUNTIME IMAGE
# ============================================================

FROM python:3.12-slim

ARG APP_VERSION=1.0.0

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_VERSION=${APP_VERSION}

WORKDIR /app


# Apply available Debian security updates.
# No pip upgrade is performed here.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# Create dedicated non-root application user.
RUN groupadd --system appuser \
    && useradd --system \
       --gid appuser \
       --create-home \
       appuser


# Copy only application runtime dependencies.
COPY --from=builder /install /usr/local


# Copy application source.
COPY core ./core
COPY web ./web
COPY main.py .


# Create writable application workspace.
RUN mkdir -p /app/web_workspace \
    && chown -R appuser:appuser /app


# Run as non-root user.
USER appuser

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "120", "web.app:app"]
