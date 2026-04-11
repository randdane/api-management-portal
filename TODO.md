# Next Steps

- [ ] **Run the full test suite and check coverage** — `uv run pytest --cov=portal --cov-report=term-missing`; fix any failures and close coverage gaps before moving on.

- [ ] **End-to-end integration test (portal + gateway together)** — spin up both services, create a user + token in the portal, and hit the gateway with a `tok_` bearer token. Validates the HMAC signing, Redis caching, and full validation pipeline.

- [ ] **Verify `GET /api/me` + `PUT /api/me`** — the README lists these endpoints; confirm they exist, work correctly, and are covered by tests.

- [ ] **OAuth2 flow smoke test** — review the callback logic, state validation, and user-linking edge cases (e.g. OAuth email already exists as a local account).

- [ ] **Production deployment prep** — review `Dockerfile`, confirm `REQUIRE_HTTPS` enforcement, verify session cookie `Secure` flag behavior across environments, and document secrets rotation.
