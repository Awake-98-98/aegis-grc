"""HTTP response helpers."""

from __future__ import annotations

from typing import Any

from fastapi import Response

from aegis.config import Settings


def ok(data: Any = None, meta: dict | None = None) -> dict:
    payload: dict[str, Any] = {"ok": True}
    if data is not None:
        payload["data"] = data
    if meta is not None:
        payload["meta"] = meta
    return payload


def page_meta(*, page: int, page_size: int, total: int) -> dict:
    pages = (total + page_size - 1) // page_size if page_size else 0
    return {"page": page, "page_size": page_size, "total": total, "pages": pages}


def set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(key=settings.cookie_name, path="/")
