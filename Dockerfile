FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files first for layer caching
COPY pyproject.toml .
COPY uv.lock* .

# Install dependencies (no dev extras in production)
RUN uv sync --no-dev --frozen

# Copy source
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .

ENV PYTHONPATH=src

EXPOSE 8001

CMD ["uv", "run", "uvicorn", "portal.main:app", "--host", "0.0.0.0", "--port", "8001"]
