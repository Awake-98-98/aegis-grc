"""Structured application logging.

A single formatter keeps CLI output and server logs readable; a request id
lets one HTTP request be followed across service calls.
"""

from __future__ import annotations

import logging
import sys
import uuid

_CONFIGURED = False


def configure_logging(level: str = "INFO") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s %(name)s [%(request_id)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    logging.LoggerAdapter  # keep import surface explicit
    _CONFIGURED = True


def new_request_id() -> str:
    return uuid.uuid4().hex[:12]


class RequestLogger(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = dict(self.extra or {})
        extra.setdefault("request_id", "-")
        kwargs["extra"] = {**extra, **kwargs.get("extra", {})}
        return msg, kwargs


def get_logger(name: str = "aegis", request_id: str | None = None) -> RequestLogger:
    return RequestLogger(logging.getLogger(name), {"request_id": request_id or "-"})
