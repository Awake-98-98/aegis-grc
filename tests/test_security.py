"""Password hashing, policy and RBAC."""

from __future__ import annotations

import pytest

from aegis.errors import ValidationFailure
from aegis.security.passwords import hash_password, validate_password, verify_password
from aegis.security.rbac import can, is_known_role, permissions_for


def test_hash_roundtrip() -> None:
    stored = hash_password("CorrectHorse1")
    assert stored.startswith("scrypt$")
    assert verify_password(stored, "CorrectHorse1") is True
    assert verify_password(stored, "correcthorse1") is False


def test_hash_is_salted() -> None:
    assert hash_password("SamePass123") != hash_password("SamePass123")


def test_verify_rejects_garbage() -> None:
    assert verify_password(None, "anything") is False
    assert verify_password("", "anything") is False
    assert verify_password("plaintext", "plaintext") is False
    assert verify_password("scrypt$broken", "x") is False


@pytest.mark.parametrize(
    "password",
    ["short1", "allletters", "123456789012", "a1" * 70],
)
def test_policy_rejects_weak_or_oversized(password: str) -> None:
    with pytest.raises(ValidationFailure):
        validate_password(password)


def test_policy_accepts_reasonable_password() -> None:
    validate_password("GoodPass123")


def test_role_permissions() -> None:
    assert can("admin", "client:write")
    assert can("consultant", "client:write")
    assert can("consultant", "stakeholder:write")
    assert not can("consultant", "user:manage")
    assert can("viewer", "client:read")
    assert not can("viewer", "client:write")
    assert not can("viewer", "stakeholder:write")
    assert is_known_role("consultant") is True
    assert is_known_role("ghost") is False
    assert permissions_for("ghost") == frozenset()
