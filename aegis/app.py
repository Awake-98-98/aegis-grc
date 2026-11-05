"""FastAPI application factory."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from aegis import __app_name__, __version__
from aegis.api import api_router
from aegis.config import Settings
from aegis.db import create_db_engine, create_session_factory, run_migrations
from aegis.errors import AppError, NotFound
from aegis.logging import configure_logging, get_logger, new_request_id
from aegis.web import web_router
from aegis.web.templating import build_templates

PACKAGE_ROOT = Path(__file__).resolve().parent


def create_app(settings: Settings | None = None, *, run_migration: bool = True) -> FastAPI:
    settings = settings or Settings.load()
    configure_logging()
    engine = create_db_engine(settings)
    if run_migration:
        run_migrations(engine)
    session_factory = create_session_factory(engine)
    templates = build_templates(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger = get_logger("aegis.app")
        logger.info(
            "started %s %s env=%s db=%s",
            __app_name__,
            __version__,
            settings.environment,
            settings.database_url,
        )
        yield
        engine.dispose()
        logger.info("stopped")

    app = FastAPI(
        title=f"{__app_name__} API",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.templates = templates

    app.mount("/static", StaticFiles(directory=PACKAGE_ROOT / "static"), name="static")

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request.state.request_id = new_request_id()
        request.state.started = time.monotonic()
        try:
            response = await call_next(request)
        except AppError:
            raise
        response.headers["X-Request-Id"] = request.state.request_id
        return response

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        wants_json = request.url.path.startswith("/api/")
        if wants_json:
            return JSONResponse(
                status_code=exc.status_code,
                content={"ok": False, "error": exc.to_dict(), "request_id": request.state.request_id},
            )
        if exc.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        status = exc.status_code if exc.status_code < 500 else 500
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "status": status,
                "error": exc.to_dict(),
                "request_id": getattr(request.state, "request_id", "-"),
                "current_user": None,
                "nav": "",
                "csrf_token": "",
            },
            status_code=status,
        )

    @app.exception_handler(NotFound)
    async def not_found_handler(request: Request, exc: NotFound):
        return await app_error_handler(request, exc)

    app.include_router(api_router)
    app.include_router(web_router)
    return app
