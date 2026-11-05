"""Health and bootstrap-status endpoints (no authentication)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from aegis import __version__
from aegis.api.deps import get_db
from aegis.api.responses import ok
from aegis.db.migrator import schema_status
from aegis.models import User
from aegis.util.time import as_iso, utcnow

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    database_ok = True
    database_error = ""
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - only on a broken database
        database_ok = False
        database_error = type(exc).__name__
    return ok(
        {
            "status": "ok" if database_ok else "degraded",
            "version": __version__,
            "schema": schema_status(db.get_bind()),
            "database": {"ok": database_ok, "error": database_error},
            "time": as_iso(utcnow()),
        }
    )


@router.get("/setup/status")
def setup_status(db: Session = Depends(get_db)) -> dict:
    initialized = (
        db.execute(select(User.id).limit(1)).scalar_one_or_none() is not None
    )
    return ok({"initialized": initialized, "version": __version__})
