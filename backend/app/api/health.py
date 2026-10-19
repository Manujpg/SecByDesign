"""Health-Endpunkte für Kubernetes-Probes und den Smoke-Test.

- ``/healthz``: Liveness. Prüft nur, dass der Prozess antwortet.
- ``/readyz``: Readiness. Prüft zusätzlich die Datenbankverbindung.

Antworten enthalten bewusst keine Versionen, Hostnamen oder Fehlerdetails (SR-05).
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.errors import error_response
from app.db import get_db

router = APIRouter(tags=["health"])
logger = logging.getLogger("app.health")


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", response_model=None)
def readyz(db: Annotated[Session, Depends(get_db)]):
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        # Nur den Fehlertyp loggen; Meldungen können Hostnamen oder Benutzernamen enthalten.
        logger.warning("Datenbank nicht erreichbar: %s", type(exc).__name__)
        return error_response(503)
    return {"status": "ok"}
