# API Management Portal

A FastAPI web portal for managing human users and opaque API tokens for an API gateway. Provides session-based authentication, self-service token management, an admin dashboard, vendor catalog browsing, and a gateway-facing token validation endpoint.

Built with FastAPI, PostgreSQL, Redis, Jinja2, and [Datastar](https://data-star.dev/) (SSE-driven hypermedia UI).

---

## Quick Start

### Prerequisites

- Python 3.12+, [uv](https://docs.astral.sh/uv/), Docker + Docker Compose
- A running instance of the API gateway at `api-gateway-middleware-centric`

### 1. Clone and configure

```bash
cp .env.example .env
# Edit .env — set SECRET_KEY, GATEWAY_PORTAL_SHARED_SECRET, GATEWAY_ADMIN_URL, etc.
```

### 2. Start with Docker Compose

```bash
docker compose up
```

This runs migrations automatically before starting the server. The portal is available at **http://localhost:8001**.

### 3. Create the first admin user

```bash
python scripts/create_admin.py <username> <email> <password>
```

---

## Running Locally (without Docker)

```bash
# Install dependencies
uv sync

# Start infrastructure
docker compose up db redis -d

# Run migrations
uv run alembic upgrade head

# Start the server
uv run uvicorn portal.main:app --host 0.0.0.0 --port 8001 --reload
```

---

## Running Tests

```bash
uv run pytest
# With coverage:
uv run pytest --cov=portal --cov-report=term-missing
```

---

## Environment Variables

Copy `.env.example` to `.env`. Key variables:

| Variable | Description | Default |
|---|---|---|
| `ENVIRONMENT` | `development` / `staging` / `production` | `development` |
| `DATABASE_URL` | PostgreSQL connection string (asyncpg) | — |
| `REDIS_URL` | Redis connection string | — |
| `SECRET_KEY` | Signs session cookies — **change in production** | — |
| `GATEWAY_ADMIN_URL` | Gateway admin API base URL | — |
| `GATEWAY_SERVICE_JWT` | Service account JWT for gateway admin API | — |
| `GATEWAY_PORTAL_SHARED_SECRET` | HMAC key shared with gateway for token validation — **change in production** | — |
| `REQUIRE_HTTPS` | Enforce HTTPS on gateway URLs; forced `true` outside `development` | `true` |
| `OAUTH2_*` | OAuth2 provider settings (all empty = OAuth2 disabled) | — |

> **Security note:** `REQUIRE_HTTPS=false` is only permitted when `ENVIRONMENT=development`. All other environments enforce HTTPS on gateway URLs and OAuth2 redirect URIs.

---

## Architecture

### Stack

- **Web framework:** FastAPI + Uvicorn
- **Database:** PostgreSQL 16 via SQLAlchemy 2.0 (async) + Alembic migrations
- **Cache / rate-limiting:** Redis 7
- **Frontend:** Jinja2 templates + [Datastar](https://data-star.dev/) SSE for reactive UI
- **HTTP client:** httpx (gateway admin API proxy)
- **Auth:** bcrypt passwords, SHA-256 hashed sessions, `tok_` prefix opaque API tokens
- **Request signing:** HMAC-SHA256 on the gateway-facing validation endpoint

### Data models

| Table | Purpose |
|---|---|
| `users` | Human users with role (`admin`/`user`) and optional OAuth2 identity |
| `api_tokens` | Opaque `tok_` tokens — only the SHA-256 hash is stored |
| `sessions` | Browser session tokens (SHA-256 hash + expiry) |
| `audit_logs` | Immutable log of all mutations with JSONB details |

### Key endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `GET /` | Session | Dashboard |
| `GET /tokens` | Session | Token management UI |
| `GET /admin/users` | Admin | User management UI |
| `GET /admin/audit-logs` | Admin | Audit log viewer |
| `GET /vendors` | Session | Vendor catalog (proxied from gateway) |
| `GET /admin/vendors` | Admin | Vendor admin UI |
| `POST /api/auth/login` | — | Username/password login |
| `POST /api/auth/logout` | Session | Invalidate session |
| `GET /api/me` | Session | Current user profile |
| `PUT /api/me` | Session | Update email / password |
| `GET /api/tokens` | Session | List tokens |
| `POST /api/tokens` | Session | Create token (plain value returned once) |
| `DELETE /api/tokens/{id}` | Session | Revoke token |
| `POST /api/tokens/validate` | HMAC | **Gateway-facing** — validate a bearer token |
| `GET /api/admin/users` | Admin | List users |
| `POST /api/admin/users` | Admin | Create user |
| `PUT /api/admin/users/{id}` | Admin | Update role / active status |
| `DELETE /api/admin/users/{id}` | Admin | Deactivate user |
| `GET /api/admin/audit-logs` | Admin | Query audit logs |
| `GET /api/vendors` | Session | List vendors |
| `POST /api/vendors` | Admin | Create vendor |
| `PUT /api/vendors/{id}` | Admin | Update vendor |
| `DELETE /api/vendors/{id}` | Admin | Deactivate vendor |
| `GET /health` | — | Liveness check (includes Redis ping) |

API docs (Swagger / ReDoc) are available at `/docs` and `/redoc` when `DEBUG=true`.

### Dual-route pattern

Token and vendor mutations expose two endpoint families:

- `/api/tokens`, `/api/vendors` — pure JSON API (gateway, curl, tests)
- Page routes + Datastar `@post`/`@put`/`@delete` calls — return SSE `datastar-merge-fragments` events so the browser receives morphable HTML fragments without a full reload

This keeps the JSON API stable for machine callers while the browser UI receives live HTML fragments.

### Gateway integration

The gateway calls `POST /api/tokens/validate` to authenticate `tok_` bearer tokens. Requests must be signed with HMAC-SHA256:

```
X-Portal-Timestamp: <unix epoch>
X-Portal-Signature: HMAC-SHA256(key, "{timestamp}\n{METHOD}\n{path}\n{sha256(body)}")
```

Requests outside a ±30-second window are rejected. The shared secret is `GATEWAY_PORTAL_SHARED_SECRET` (portal) / `PORTAL_SHARED_SECRET` (gateway).

### Security

- **CSRF:** Double-submit cookie pattern — a plain token in a non-HttpOnly cookie is echoed as `X-CSRF-Token` on every mutating request via a global `fetch` interceptor in `base.html`.
- **Rate limiting:** Redis-backed, 5 login attempts per minute per IP.
- **Session cookies:** `HttpOnly`, `SameSite=Lax`, `Secure` in production.
- **Audit log:** Every user, token, and vendor mutation is recorded with actor, IP, and a JSONB details payload. Logs are append-only (no update/delete routes).

### Secrets Rotation

- **`SECRET_KEY`**: Rotating this key invalidates all active sessions. Users will be logged out and must log in again.
- **`GATEWAY_PORTAL_SHARED_SECRET`**: This must be updated in tandem on both the Portal and the Gateway. Coordinated restart or environment update is required.
- **`GATEWAY_SERVICE_JWT`**: To rotate, generate a new service account JWT on the Gateway and update the `GATEWAY_SERVICE_JWT` environment variable on the Portal.

---

## Project Structure

```
src/portal/
├── main.py                  # App factory, lifespan, middleware stack
├── config.py                # Pydantic settings (all env vars)
├── sse.py                   # Datastar SSE helpers
├── auth/                    # passwords, sessions, tokens, HMAC, OAuth2
├── cache/                   # Redis client
├── db/                      # SQLAlchemy models and async session
├── middleware/              # CSRF and rate-limit middleware
├── routes/                  # FastAPI routers
├── services/                # audit.py, gateway_client.py
├── static/                  # styles.css
└── templates/               # Jinja2 HTML + fragments/

alembic/                     # Async Alembic migrations
scripts/create_admin.py      # Seed first admin user
tests/                       # pytest suite
```

---

## Database Migrations

```bash
# Apply all migrations
uv run alembic upgrade head

# Create a new migration (after editing models.py)
uv run alembic revision --autogenerate -m "describe_change"

# Roll back one step
uv run alembic downgrade -1
```
