"""ASGI-Middleware für Request-ID, Security-Header, Zugriffslog und 500-Fallback.

Bewusst als reine ASGI-Middleware (statt BaseHTTPMiddleware) umgesetzt, damit
auch Antworten auf unerwartete Ausnahmen Request-ID und Security-Header tragen.
"""

from __future__ import annotations

import logging
import time
import uuid

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import error_response
from app.core.logging import request_id_ctx

logger = logging.getLogger("app.access")
error_logger = logging.getLogger("app.error")

# Header für eine JSON-API (SR-09). HSTS setzt der Ingress, weil nur er TLS terminiert.
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

# Die Swagger-UI (nur im Entwicklungsmodus aktiv) braucht Skripte und darf daher
# nicht unter die strikte API-CSP fallen.
_DOCS_PATHS = ("/docs", "/openapi.json")


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Die Request-ID wird immer serverseitig erzeugt. Eine vom Client
        # mitgeschickte ID wird ignoriert, damit Logs nicht manipulierbar sind.
        request_id = uuid.uuid4().hex
        token = request_id_ctx.set(request_id)
        path: str = scope.get("path", "")
        is_docs = path.startswith(_DOCS_PATHS)
        started = time.perf_counter()
        status_code = 500
        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                for name, value in SECURITY_HEADERS.items():
                    if is_docs and name == "Content-Security-Policy":
                        continue
                    if name not in headers:
                        headers[name] = value
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            error_logger.exception("unbehandelte Ausnahme", extra={"event": "unhandled_exception"})
            if response_started:
                raise
            await error_response(500)(scope, receive, send_wrapper)
        finally:
            logger.info(
                "request",
                extra={
                    "event": "access",
                    "method": scope.get("method"),
                    "path": path,  # bewusst ohne Query-String (kann Personendaten enthalten)
                    "status": status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )
            request_id_ctx.reset(token)
