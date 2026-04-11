# API Management Portal — Design Spec

## Context

An existing API gateway (`api-gateway-middleware-centric`) handles JWT-based authentication for service accounts (non-human). There is currently no way for human users to authenticate with the gateway. This portal fills that gap — it manages users and issues opaque API tokens that humans use to access the gateway. The gateway validates these tokens by calling back to the portal.

The portal also provides a web UI for managing tokens, browsing available vendors/endpoints, viewing usage stats, and administering users — functionality that currently requires direct admin API calls to the gateway.

## Architecture

### System Boundaries

Two independent FastAPI applications, each with its own PostgreSQL database:

- **Management Portal** (this project) — owns users, tokens, sessions, audit logs. Serves the Datastar-powered UI. Exposes a token validation endpoint for the gateway.
- **API Gateway** (existing) — unchanged except for one addition: when it sees a non-JWT bearer token (prefixed `tok_`), it validates it by calling the portal's `/api/tokens/validate` endpoint, with Redis caching (~60s TTL).

### Communication

| From | To | Method | Purpose |
|------|----|--------|---------|
| Human (browser) | Portal | HTTPS + cookies | UI interaction, login, token management |
| Human (API client) | Gateway | HTTPS + Bearer token | API calls using opaque token |
| Gateway | Portal | HTTPS POST (+ HMAC) | Token validation (`/api/tokens/validate`) |
| Portal | Gateway | HTTPS GET (+ JWT) | Fetch vendor catalog, quota stats via gateway admin API |

**Transport security requirements:**

- **Production:** All hops MUST use HTTPS/TLS. The HMAC signature on the validate endpoint authenticates the caller and (via the signed timestamp) provides a short freshness window, but it is NOT a replacement for transport encryption. Sending bearer tokens over plain HTTP in production would expose them to any network observer regardless of whether individual requests are signed.
- **Development (localhost only):** Plain HTTP between portal and gateway is acceptable because traffic never leaves the loopback interface. The HMAC check still runs, so misconfiguration (e.g., accidentally pointing a dev gateway at a non-localhost portal URL) is caught by signature validation rather than silently succeeding.
- **Enforcement:** The portal's config includes a `REQUIRE_HTTPS` flag (default `True`, overridable to `False` only in `ENVIRONMENT=development`). When enabled, the portal refuses to start if `GATEWAY_ADMIN_URL` is not `https://`, and the gateway refuses to start if `PORTAL_URL` is not `https://`. This prevents production from silently running unencrypted.
- **Certificate handling:** For internal service-to-service TLS, either use a public CA, an internal CA with both sides trusting it, or (as the natural production upgrade path) mTLS as described in the validate endpoint section.

### Key Design Decisions

- **Portal owns the database.** The gateway never touches the portal's DB — it validates tokens exclusively via HTTP.
- **Opaque tokens, not JWTs.** Human tokens are random strings (`tok_` prefix), hashed (SHA-256) for storage. This avoids key management complexity and enables instant revocation.
- **Cached validation.** The gateway caches valid token responses in Redis (configurable TTL, default 60s). Revocation takes effect within the TTL window.
- **Datastar frontend.** Server-rendered HTML with Datastar for reactivity. No JavaScript build step, no SPA framework. The backend returns HTML fragments via SSE.

## Data Model

### `users`

| Column | Type | Notes |
|--------|------|-------|
| id | UUID | PK |
| email | VARCHAR | UNIQUE |
| username | VARCHAR | UNIQUE |
| password_hash | VARCHAR | NULLABLE — empty for OAuth users |
| oauth_provider | VARCHAR | NULLABLE — e.g., "google", "auth0" |
| oauth_subject | VARCHAR | NULLABLE — provider's user ID |
| role | ENUM | `admin` or `user` |
| is_active | BOOLEAN | Soft disable |
| created_at | TIMESTAMP | |
| updated_at | TIMESTAMP | |

Supports both auth methods. Password users have `password_hash`; OAuth users have `oauth_provider` + `oauth_subject`. A user could have both if they link accounts later.

**Constraint:** `UNIQUE(oauth_provider, oauth_subject)` partial index (WHERE both are NOT NULL). This prevents the same external identity from being linked to multiple local users, which would make OAuth callback resolution nondeterministic and allow account-linking races.

### `api_tokens`

| Column | Type | Notes |
|--------|------|-------|
| id | UUID | PK |
| user_id | UUID | FK → users.id |
| name | VARCHAR | User-assigned label |
| token_hash | VARCHAR | SHA-256 of the full token |
| token_prefix | VARCHAR | First 8 chars (e.g., `tok_a3bf`) for display |
| expires_at | TIMESTAMP | NULLABLE — null means no expiry |
| last_used_at | TIMESTAMP | NULLABLE — best-effort, not authoritative (see below) |
| is_revoked | BOOLEAN | |
| created_at | TIMESTAMP | |

The plain token is shown once at creation and never stored. Only the hash is persisted. The prefix lets users identify tokens in the UI.

**`last_used_at` accuracy caveat:** Because the gateway caches successful validations in Redis (~60s TTL), most real token uses will not hit the portal's validate endpoint, so `last_used_at` would be systematically stale for active tokens if only updated there. Two options:

- **MVP approach:** Update `last_used_at` only when validation hits the portal (cache miss). Label the field as "last seen by portal" in the UI, and note that a value within the last ~60s could mean active use up to ~60s ago, or continuous use with only cache-miss updates. Do not expose precise usage counts.
- **Accurate option (if needed later):** Add a usage-reporting path where the gateway pushes async usage events (via Redis stream or HTTP batch) to the portal. The portal aggregates these into a `token_usage_events` table independent of `last_used_at`. Out of scope for the MVP.

The MVP uses option 1. The UI must not claim "precise usage stats" — it shows "last seen" with an explanatory tooltip.

### `sessions`

| Column | Type | Notes |
|--------|------|-------|
| id | UUID | PK |
| user_id | UUID | FK → users.id |
| session_token_hash | VARCHAR | SHA-256 of session cookie value |
| ip_address | VARCHAR | NULLABLE |
| user_agent | VARCHAR | NULLABLE |
| expires_at | TIMESTAMP | |
| created_at | TIMESTAMP | |

DB-backed sessions enable server-side revocation and security visibility.

### `audit_logs`

| Column | Type | Notes |
|--------|------|-------|
| id | UUID | PK |
| user_id | UUID | FK → users.id, NULLABLE (system actions) |
| action | VARCHAR | e.g., `token.created`, `user.deactivated` |
| resource_type | VARCHAR | e.g., `token`, `user` |
| resource_id | VARCHAR | NULLABLE |
| details | JSONB | Additional context |
| ip_address | VARCHAR | NULLABLE |
| created_at | TIMESTAMP | |

Append-only. All mutations are logged.

## API Design

### Internal (called by gateway)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/tokens/validate` | Validate opaque token, return user identity + role |

**Request:** `{ "token": "tok_a3bf8c..." }`
**Response (valid):** `{ "valid": true, "user_id": "<uuid>", "email": "user@example.com", "role": "user" }`
**Response (invalid):** `{ "valid": false }`

**Caller authentication (required):** This endpoint MUST authenticate the caller. Without authentication, it becomes a token oracle — an attacker could probe `tok_` values and harvest user identities for valid ones. Two acceptable mechanisms:

1. **Shared HMAC signature with freshness (minimum):** The gateway computes HMAC-SHA256 over a canonical string that includes a timestamp, HTTP method, request path, and request body. Headers:
   - `X-Portal-Timestamp`: Unix epoch seconds
   - `X-Portal-Signature`: `hex(HMAC-SHA256(secret, "{timestamp}\n{METHOD}\n{path}\n{sha256(body)}"))`

   The portal validates by: (a) rejecting requests where `|now - timestamp| > 30` seconds (acceptance window), (b) recomputing the HMAC over the same canonical string and comparing in constant time. Including the timestamp gives freshness, including method + path prevents cross-endpoint replay, and binding the body hash prevents tampering. A nonce cache is not required for the MVP because the 30-second window is narrow and the endpoint is idempotent, but could be added later if stricter replay resistance is needed. The shared secret is `GATEWAY_PORTAL_SHARED_SECRET`, configured via environment variables on both sides.

2. **mTLS (preferred for production):** Both sides present client/server certificates from a trusted CA. Freshness and binding are handled by the TLS session itself.

The portal rejects unauthenticated, out-of-window, or invalid-signature calls with 401. For the MVP/demo, HMAC is the default; mTLS is a deployment-time upgrade with no code changes beyond Uvicorn/reverse proxy config.

### Authentication

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/auth/login` | Username/password login → session cookie |
| POST | `/api/auth/logout` | Invalidate session |
| GET | `/api/auth/oauth2/authorize` | Redirect to OAuth provider |
| GET | `/api/auth/oauth2/callback` | Handle OAuth return, create session |

### Token Management

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/tokens` | List current user's tokens |
| POST | `/api/tokens` | Create token (returns plain token once) |
| DELETE | `/api/tokens/{id}` | Revoke a token |

### User Self-Service

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/me` | Current user profile |
| PUT | `/api/me` | Update profile |

### Admin (admin role required)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/admin/users` | List all users |
| POST | `/api/admin/users` | Create/invite user |
| PUT | `/api/admin/users/{id}` | Update user (role, active status) |
| DELETE | `/api/admin/users/{id}` | Deactivate user |
| GET | `/api/admin/audit-logs` | Query audit log (filterable) |

### Gateway Proxy (portal reads from gateway)

The portal calls the gateway's existing admin API to populate the UI:
- `GET /admin/vendors` — vendor catalog
- `GET /admin/vendors/{id}` — vendor detail + endpoints
- `GET /admin/vendors/{id}/quota` — quota/usage stats

These are presented read-only to regular users in the vendor catalog. Admins get full CRUD through the same proxy.

The portal authenticates to the gateway's admin API using a service account JWT (the gateway's existing auth mechanism). The portal holds a service account credential configured via environment variable.

**Transport:** These calls MUST use HTTPS in production. Sending a service account JWT over plain HTTP would expose a reusable credential to any network observer. The portal enforces this at startup via the `REQUIRE_HTTPS` flag (see Gateway Modification section).

## Frontend

### Technology

- **Rendering:** Jinja2 templates served by FastAPI
- **Reactivity:** Datastar (single `<script>` tag, ~12KB)
- **Styling:** Simple CSS (no framework required for MVP, can add later)
- **No build step:** No npm, no bundler, no node_modules

### Pages

| Page | Path | Access | Description |
|------|------|--------|-------------|
| Login | `/login` | Public | Username/password form, OAuth link |
| Dashboard | `/` | Authenticated | Overview: token count, recent activity |
| Tokens | `/tokens` | Authenticated | List, create, revoke API tokens |
| Vendor Catalog | `/vendors` | Authenticated | Browse vendors and endpoints |
| Admin: Users | `/admin/users` | Admin | User management table |
| Admin: Vendors | `/admin/vendors` | Admin | Vendor CRUD (proxied to gateway) |
| Admin: Audit Log | `/admin/audit-logs` | Admin | Filterable audit log |

### Datastar Patterns

- **SSE fragments:** All form submissions and interactions return HTML fragments via SSE that Datastar morphs into the DOM. No JSON consumed by the frontend.
- **Signals:** Form state managed via `data-signals` and `data-bind` (e.g., `$search`, `$tokenName`).
- **Indicators:** `data-indicator` for loading states during submissions.
- **Debounced search:** `data-on:input__debounce.300ms` for filtering tables.
- **Show/hide:** `data-show` for conditional UI (admin sections, confirmation dialogs).

### Page Load vs Interaction

Initial page loads return full HTML documents. Subsequent interactions (form submissions, search, pagination) return SSE fragment responses that update specific parts of the page. Same FastAPI endpoint handles both — it checks whether the request is an SSE request and responds accordingly.

## Gateway Modification

### Scope

Minimal change to the existing gateway:

1. **Auth dependency branch** (`src/gateway/auth/dependencies.py`): If the bearer token starts with `tok_`, validate via portal. Otherwise, proceed with existing JWT/JWKS validation.
2. **New `PortalTokenValidator` class**: Calls `POST <portal_url>/api/tokens/validate` with HMAC signature header, caches results in Redis.
3. **New config settings**: `PORTAL_URL` (default: `http://localhost:8001` — **local development only**; production MUST be `https://...`), `PORTAL_SHARED_SECRET` (HMAC key, must match portal's `GATEWAY_PORTAL_SHARED_SECRET`), `PORTAL_TOKEN_CACHE_TTL` (default 60), `REQUIRE_HTTPS` (default `True` outside development).

**Startup check:** When `REQUIRE_HTTPS=True`, the gateway refuses to start if `PORTAL_URL` does not begin with `https://`. Similarly, the portal refuses to start if `GATEWAY_ADMIN_URL` is not HTTPS. This prevents production from silently running with unencrypted inter-service traffic. The `http://localhost:8001` default exists solely so a developer can bring up both services on loopback without TLS setup.

### What Doesn't Change

- JWT/JWKS validation for service accounts
- Middleware stack (tracing, logging, rate limiting)
- Vendor routing and proxy logic
- Admin API endpoints
- The `UserIdentity` dataclass — portal validation response maps directly to its fields

### Token Format Detection

- Tokens starting with `tok_` → portal validation
- All other bearer tokens → existing JWT validation

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend framework | FastAPI |
| Frontend reactivity | Datastar |
| Templates | Jinja2 |
| Database | PostgreSQL (separate from gateway) |
| ORM | SQLAlchemy 2.0 (async) |
| Migrations | Alembic |
| Password hashing | bcrypt (via passlib) |
| HTTP client | httpx (async, for gateway admin API calls) |
| Session management | DB-backed with secure cookies |

## Verification Plan

1. **Unit tests:** Token hashing, validation logic, role checks, session lifecycle
2. **Integration tests:** Full auth flow (login → create token → use token at gateway → validate callback)
3. **Manual testing:**
   - Create a user, log in, generate a token
   - Use the token in a curl request to the gateway
   - Verify the gateway calls back to the portal and the request succeeds
   - Revoke the token, wait for cache TTL, verify the gateway rejects it
   - Test admin flows: create/deactivate users, view audit logs
4. **Datastar UI testing:** Verify SSE fragments morph correctly, forms submit, tables filter
