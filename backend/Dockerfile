FROM python:3.12-slim

WORKDIR /app

# System deps for lxml etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and install deps first (cache-friendly layer)
COPY pyproject.toml ./
COPY backend/src ./backend/src
COPY README.md LICENSE ./

RUN pip install --no-cache-dir -e .

# Data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "t1_cve_enricher.main:app", "--host", "0.0.0.0", "--port", "8000"]
