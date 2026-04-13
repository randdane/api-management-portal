from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from portal.cache.redis import close_redis, get_client, init_redis
from portal.config import settings
from portal.db.session import engine
from portal.logging_config import configure_logging
from portal.middleware.csrf import CSRFMiddleware
from portal.middleware.rate_limit import LoginRateLimitMiddleware
from portal.routes.admin import router as admin_router
from portal.routes.auth import me_router, router as auth_router
from portal.routes.oauth2 import router as oauth2_router
from portal.routes.pages import router as pages_router
from portal.routes.tokens import router as tokens_router
from portal.routes.validate import router as validate_router
from portal.routes.vendors import router as vendors_router

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "portal.starting",
        environment=settings.environment,
        require_https=settings.require_https,
    )

    init_redis()
    logger.info("portal.redis.connected")

    app.state.http_client = httpx.AsyncClient(timeout=10.0)

    yield

    await app.state.http_client.aclose()
    await close_redis()
    await engine.dispose()
    logger.info("portal.stopped")


def create_app() -> FastAPI:
    configure_logging()

    # Fail-fast if using default secrets outside development.
    if settings.environment != "development":
        insecure_secrets = []
        if settings.secret_key == "dev-secret-change-me-in-production":
            insecure_secrets.append("SECRET_KEY")
        if (
            settings.gateway_portal_shared_secret
            == "dev-shared-secret-change-me-in-production"
        ):
            insecure_secrets.append("GATEWAY_PORTAL_SHARED_SECRET")

        if insecure_secrets:
            logger.critical(
                "portal.insecure_configuration",
                environment=settings.environment,
                insecure_secrets=insecure_secrets,
                error="Default secrets are not permitted outside of development.",
            )
            raise RuntimeError(
                f"Insecure configuration: {', '.join(insecure_secrets)} are using default values. "
                "You must provide unique, secure secrets for non-development environments."
            )

    app = FastAPI(
        title="API Management Portal",
        description="Human user & token management for the API gateway",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # Middleware — add_middleware wraps in reverse order (last = outermost).
    # CSRF runs outermost so it can reject before rate limiting increments.
    app.add_middleware(LoginRateLimitMiddleware)
    app.add_middleware(CSRFMiddleware)

    app.mount("/static", StaticFiles(directory="src/portal/static"), name="static")

    app.include_router(pages_router)
    app.include_router(auth_router)
    app.include_router(me_router)
    app.include_router(validate_router)
    app.include_router(tokens_router)
    app.include_router(admin_router)
    app.include_router(vendors_router)
    app.include_router(oauth2_router)
    _register_routes(app)
    return app


def _register_routes(app: FastAPI) -> None:
    @app.get("/health", include_in_schema=False)
    async def health() -> JSONResponse:
        status: dict = {"status": "ok", "services": {}}

        try:
            client = get_client()
            await client.ping()
            await client.aclose()
            status["services"]["redis"] = "ok"
        except Exception as exc:
            status["services"]["redis"] = f"error: {exc}"
            status["status"] = "degraded"

        return JSONResponse(status)


app = create_app()
