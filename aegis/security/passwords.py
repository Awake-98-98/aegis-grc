"""Password hashing and password policy.

``hashlib.scrypt`` is part of the standard library, so the project has no
native dependency and stays installable on a clean machine. Parameters are
encoded in the stored value, which makes a future cost bump a rolling
migration rather than a flag day.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from aegis.errors import ValidationFailure

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
_DKLEN = 32
_PREFIX = "scrypt"
_MIN_LENGTH = 10
_MAX_LENGTH = 128


def hash_password(password: str, *, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=_DKLEN
    )
    return f"{_PREFIX}${n}${r}${p}${salt.hex()}${digest.hex()}"


def verify_password(stored: str | None, password: str) -> bool:
    if not stored or not password:
        return False
    try:
        prefix, n_raw, r_raw, p_raw, salt_hex, digest_hex = stored.split("$")
        if prefix != _PREFIX:
            return False
        expected = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n_raw),
            r=int(r_raw),
            p=int(p_raw),
            dklen=len(bytes.fromhex(digest_hex)),
        )
        return hmac.compare_digest(expected.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def validate_password(password: str) -> None:
    """Raise ValidationFailure when a password does not meet policy."""
    if not isinstance(password, str) or not password.strip():
        raise ValidationFailure("password is required", details={"field": "password"})
    if len(password) < _MIN_LENGTH:
        raise ValidationFailure(
            f"password must be at least {_MIN_LENGTH} characters",
            details={"field": "password", "min_length": _MIN_LENGTH},
        )
    if len(password) > _MAX_LENGTH:
        raise ValidationFailure(
            f"password must be at most {_MAX_LENGTH} characters",
            details={"field": "password", "max_length": _MAX_LENGTH},
        )
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValidationFailure(
            "password must contain at least one letter and one digit",
            details={"field": "password"},
        )
