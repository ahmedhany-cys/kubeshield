# syntax=docker/dockerfile:1.7
# KubeShield API + dashboard image.

FROM docker.io/library/node:24-alpine AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM docker.io/aquasec/trivy:0.76.1 AS trivy

FROM docker.io/library/python:3.13-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY backend/pyproject.toml backend/README.md ./
COPY backend/kubeshield ./kubeshield
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --upgrade pip && /opt/venv/bin/pip install .

FROM docker.io/library/python:3.13-slim
LABEL org.opencontainers.image.title="KubeShield" \
      org.opencontainers.image.description="Kubernetes runtime threat detection and automated response" \
      org.opencontainers.image.source="https://github.com/ahmedhany-cys/kubeshield" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 kubeshield && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin kubeshield
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /opt/venv /opt/venv
COPY --from=frontend /src/dist /app/static
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KUBESHIELD_STATIC_DIR=/app/static \
    KUBESHIELD_TRIVY_CACHE_DIR=/var/cache/trivy \
    HOME=/tmp
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["uvicorn", "kubeshield.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
