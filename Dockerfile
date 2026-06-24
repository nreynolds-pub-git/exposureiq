# syntax=docker/dockerfile:1.7

# ============================================================================
# Stage 1: Build the frontend
# ============================================================================
FROM node:22-alpine AS frontend-build

WORKDIR /build

# Copy only manifest first so dep-install layer caches across code changes
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

# Now copy the rest and build
COPY frontend/ ./
RUN npm run build
# Produces /build/dist/ — Vite's default output path

# ============================================================================
# Stage 2: Python backend, with built frontend baked in
# ============================================================================
FROM python:3.12-slim AS runtime

# Minimal runtime tooling: sqlite3 for the init-db path, curl for healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        sqlite3 \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install backend deps first (separate layer for caching).
# pyproject.toml declares 'license = { file = "LICENSE" }' and 'readme = "README.md"',
# so hatchling needs both files in the build context to validate package metadata.
COPY pyproject.toml LICENSE README.md ./
COPY backend/ ./backend/
RUN pip install --no-cache-dir -e .

# Copy the built frontend bundle from stage 1 into a path the backend can serve
COPY --from=frontend-build /build/dist ./frontend/dist

# Data directory is a mount point at runtime; we create it so the schema-init
# path doesn't fail on a fresh container.
RUN mkdir -p /app/data

# Run as a non-root user (good hygiene for self-hosted deployments)
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

EXPOSE 8000

# uvicorn directly is fine for a self-hosted internal tool; no gunicorn needed.
CMD ["uvicorn", "t1_cve_enricher.main:app", "--host", "0.0.0.0", "--port", "8000"]
