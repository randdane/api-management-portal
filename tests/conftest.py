"""Shared test fixtures.

These tests exercise the HMAC dependency and validate endpoint without
requiring a live PostgreSQL database. We use FastAPI dependency overrides
to swap in a fake DB session and a fake Redis client. The HMAC-failure
tests never reach the DB, so their override is a no-op.
"""

import os

# Set a deterministic shared secret BEFORE importing the app so
# the settings singleton picks it up.
os.environ.setdefault("GATEWAY_PORTAL_SHARED_SECRET", "test-secret")
os.environ.setdefault("REQUIRE_HTTPS", "false")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
# The test client never touches the real engine, but the engine is created
# at import time so it must at least parse as a URL.
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://portal:portal@localhost:5432/portal_test"
)
