"""CSRF-Schutz über Origin-Prüfung (SR-07).

Zusätzlich zu ``SameSite=Strict`` am Sitzungscookie müssen alle zustandsändernden
Requests (POST, PUT, PATCH, DELETE) auf /api/ einen ``Origin``- (oder hilfsweise
``Referer``-)Header aus der Allowlist tragen. Fehlen beide, wird abgelehnt: Browser
senden bei solchen Requests immer mindestens einen der beiden Header.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.errors import error_response

logger = logging.getLogger("app.security")

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _origin_from_referer(referer: str | None) -> str | None:
    if not referer:
        return None
    parts = urlsplit(referer)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


class OriginCheckMiddleware:
    def __init__(self, app: ASGIApp, allowed_origins: frozenset[str]) -> None:
        self.app = app
        self.allowed = frozenset(o.lower() for o in allowed_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "http"
            and scope["method"] in UNSAFE_METHODS
            and scope.get("path", "").startswith("/api/")
        ):
            headers = Headers(scope=scope)
            origin = headers.get("origin") or _origin_from_referer(headers.get("referer"))
            if origin is None or origin.lower() not in self.allowed:
                logger.warning(
                    "Request mit unzulässigem Origin abgelehnt", extra={"event": "origin_rejected"}
                )
                response = error_response(
                    403, "origin_rejected", "Die Anfrage stammt aus einer nicht erlaubten Quelle."
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
