"""Opaque session tokens.

The plaintext token exists only in the browser cookie or the bearer header.
The database stores a SHA-256 digest, so a leaked database cannot be replayed
as a live session. CSRF tokens are stored separately and never leave the
server except in the authenticated response body or a hidden form field.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

TOKEN_BYTES = 32


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(24)


def csrf_matches(expected: str | None, provided: str | None) -> bool:
    if not expected or not provided:
        return False
    return hmac.compare_digest(expected, provided)
