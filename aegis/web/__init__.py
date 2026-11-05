"""Web console package."""

from .routes import router as web_router
from .templating import build_templates

__all__ = ["build_templates", "web_router"]
