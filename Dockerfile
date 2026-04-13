FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=src
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Create a non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser -m appuser

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock* ./

# Install dependencies (no dev extras in production)
RUN uv sync --no-dev --frozen

# Copy source and migrations
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .

# Ensure appuser owns the app directory
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

EXPOSE 8001

# Healthcheck to monitor app status
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python", "-m", "httpx", "http://localhost:8001/health"]

# Use the venv binary directly for production performance and security
CMD ["uvicorn", "portal.main:app", "--host", "0.0.0.0", "--port", "8001"]
