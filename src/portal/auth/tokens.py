"""Opaque API token generation and hashing.

Tokens have the format `tok_<random>` where random is 32 bytes of
secrets.token_urlsafe. The plaintext token is returned once at creation
and never persisted. The database stores only the SHA-256 hash.
"""

import hashlib
import secrets

TOKEN_PREFIX = "tok_"
DISPLAY_PREFIX_LEN = 8  # e.g. "tok_a3bf" — shown to the user in the UI


def generate_token() -> tuple[str, str, str]:
    """Generate a new API token.

    Returns: (plain_token, token_hash, token_prefix)
    - plain_token: the full token to show the user once
    - token_hash: SHA-256 hex, stored in DB
    - token_prefix: first 8 chars of plain_token, for UI display
    """
    random_part = secrets.token_urlsafe(32)
    plain = f"{TOKEN_PREFIX}{random_part}"
    token_hash = hash_token(plain)
    token_prefix = plain[:DISPLAY_PREFIX_LEN]
    return plain, token_hash, token_prefix


def hash_token(plain: str) -> str:
    """Return SHA-256 hex digest of the plaintext token."""
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def is_portal_token(token: str) -> bool:
    """Return True if the token looks like a portal-issued opaque token."""
    return token.startswith(TOKEN_PREFIX)
