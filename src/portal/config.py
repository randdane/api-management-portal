from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "info"
    debug: bool = False
    require_https: bool = True

    # Database
    database_url: str = "postgresql+asyncpg://portal:portal@localhost:5432/portal"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout: int = 30

    # Redis
    redis_url: str = "redis://localhost:6379/1"
    redis_max_connections: int = 50

    # Session management
    secret_key: str = "dev-secret-change-me-in-production"
    session_ttl_seconds: int = 86400
    session_cookie_name: str = "portal_session"

    # Gateway integration
    gateway_admin_url: str = "http://localhost:8000"
    gateway_service_jwt: str = ""

    # HMAC shared secret for the validate endpoint. Must match the gateway's
    # PORTAL_SHARED_SECRET configuration.
    gateway_portal_shared_secret: str = "dev-shared-secret-change-me-in-production"
    hmac_timestamp_window_seconds: int = 30

    # OAuth2 (optional — all fields empty = OAuth2 disabled)
    oauth2_client_id: str = ""
    oauth2_client_secret: str = ""
    oauth2_provider_name: str = ""
    oauth2_authorize_url: str = ""
    oauth2_token_url: str = ""
    oauth2_userinfo_url: str = ""
    oauth2_scopes: str = "openid email profile"
    oauth2_redirect_uri: str = "http://localhost:8001/api/auth/oauth2/callback"

    @model_validator(mode="after")
    def _enforce_https_in_production(self) -> "Settings":
        """Enforce HTTPS rules in both directions.

        - If REQUIRE_HTTPS is True and GATEWAY_ADMIN_URL is not HTTPS, refuse
          to start. Sending service account JWTs over plain HTTP exposes
          reusable credentials.
        - If REQUIRE_HTTPS is False and ENVIRONMENT is not "development", refuse
          to start. Disabling HTTPS outside a local dev context is a
          misconfiguration that must be explicit, not accidental.
        """
        if self.require_https and not self.gateway_admin_url.startswith("https://"):
            raise ValueError(
                "REQUIRE_HTTPS is enabled but GATEWAY_ADMIN_URL is not HTTPS. "
                "Set REQUIRE_HTTPS=false only for local development on loopback."
            )
        if not self.require_https and self.environment != "development":
            raise ValueError(
                "REQUIRE_HTTPS=false is only permitted when ENVIRONMENT=development. "
                "All non-development environments must use HTTPS."
            )
        if (
            self.require_https
            and self.oauth2_client_id
            and not self.oauth2_redirect_uri.startswith("https://")
        ):
            raise ValueError(
                "REQUIRE_HTTPS is enabled but OAUTH2_REDIRECT_URI is not HTTPS. "
                "OAuth2 redirect URIs must use HTTPS in non-development environments."
            )
        return self

    @field_validator("secret_key", "gateway_portal_shared_secret")
    @classmethod
    def _warn_default_secrets(cls, v: str) -> str:
        # Accept dev defaults but return the value unchanged. A runtime check
        # in main.py emits a warning if defaults are used outside development.
        return v


settings = Settings()
