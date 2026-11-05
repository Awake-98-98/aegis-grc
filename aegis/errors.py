"""Application error taxonomy.

Every expected failure carries a stable code so the CLI, the JSON API and the
web UI can render the same diagnosis. Unexpected failures are deliberately
generic: stack traces stay in the server log, never in an HTTP response.
"""

from __future__ import annotations

from typing import Any


class ErrorCode:
    CONFIG_INVALID = "AEG-1001"
    NOT_FOUND = "AEG-2001"
    CONFLICT = "AEG-2002"
    VALIDATION = "AEG-2003"
    UNAUTHORIZED = "AEG-3001"
    FORBIDDEN = "AEG-3002"
    CSRF_FAILED = "AEG-3003"
    RATE_LIMITED = "AEG-3004"
    ACCOUNT_INACTIVE = "AEG-3005"
    STATE_TRANSITION = "AEG-4001"
    DATABASE = "AEG-5001"
    INTERNAL = "AEG-5002"


class AppError(Exception):
    code = ErrorCode.INTERNAL
    status_code = 500
    default_message = "internal error"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
        status_code: int | None = None,
    ) -> None:
        self.message = message or self.default_message
        self.details = details or {}
        if status_code is not None:
            self.status_code = status_code
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


class ConfigFailure(AppError):
    code = ErrorCode.CONFIG_INVALID
    status_code = 500
    default_message = "configuration is invalid"


class ValidationFailure(AppError):
    code = ErrorCode.VALIDATION
    status_code = 422
    default_message = "validation failed"


class NotFound(AppError):
    code = ErrorCode.NOT_FOUND
    status_code = 404
    default_message = "resource not found"


class Conflict(AppError):
    code = ErrorCode.CONFLICT
    status_code = 409
    default_message = "resource already exists"


class Unauthorized(AppError):
    code = ErrorCode.UNAUTHORIZED
    status_code = 401
    default_message = "authentication required"


class Forbidden(AppError):
    code = ErrorCode.FORBIDDEN
    status_code = 403
    default_message = "permission denied"


class CsrfFailure(AppError):
    code = ErrorCode.CSRF_FAILED
    status_code = 403
    default_message = "invalid or missing CSRF token"


class RateLimited(AppError):
    code = ErrorCode.RATE_LIMITED
    status_code = 429
    default_message = "too many attempts, try again later"


class AccountInactive(AppError):
    code = ErrorCode.ACCOUNT_INACTIVE
    status_code = 403
    default_message = "account is inactive"


class StateTransition(AppError):
    code = ErrorCode.STATE_TRANSITION
    status_code = 409
    default_message = "state transition is not allowed"


class DatabaseFailure(AppError):
    code = ErrorCode.DATABASE
    status_code = 500
    default_message = "database operation failed"
