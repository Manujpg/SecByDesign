"""Einheitliche Fehlerbehandlung ohne Informationslecks (SR-05).

Jede Fehlerantwort hat dieselbe Form:

    {"error": {"code": "...", "message": "...", "request_id": "..."}}

- Fachliche Fehler werfen ``AppError`` mit einer bewusst für Clients formulierten Meldung.
- Framework-Fehler (404, 405, ...) bekommen generische Texte; ``detail`` wird ignoriert.
- Validierungsfehler nennen nur Feld und Fehlertyp, nie den eingegebenen Wert.
- Unerwartete Ausnahmen behandelt ``RequestContextMiddleware`` (generischer 500).
"""

from __future__ import annotations

from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import request_id_ctx

_GENERIC_MESSAGES: dict[int, tuple[str, str]] = {
    400: ("bad_request", "Die Anfrage ist ungültig."),
    401: ("unauthorized", "Bitte melden Sie sich an."),
    403: ("forbidden", "Für diese Aktion fehlt die Berechtigung."),
    404: ("not_found", "Die angeforderte Ressource wurde nicht gefunden."),
    405: ("method_not_allowed", "Diese Methode ist hier nicht erlaubt."),
    409: ("conflict", "Die Anfrage steht im Konflikt mit dem aktuellen Zustand."),
    413: ("payload_too_large", "Die Anfrage ist zu groß."),
    415: ("unsupported_media_type", "Dieses Datenformat wird nicht unterstützt."),
    422: ("validation_error", "Die Eingaben sind ungültig."),
    423: ("locked", "Das Konto ist vorübergehend gesperrt."),
    429: ("too_many_requests", "Zu viele Anfragen. Bitte versuchen Sie es später erneut."),
    500: ("internal_error", "Ein interner Fehler ist aufgetreten."),
    503: ("service_unavailable", "Der Dienst ist vorübergehend nicht verfügbar."),
}


class AppError(Exception):
    """Fachlicher Fehler mit client-tauglicher Meldung."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message


def error_response(
    status_code: int,
    code: str | None = None,
    message: str | None = None,
    details: list[dict[str, str]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    default_code, default_message = _GENERIC_MESSAGES.get(
        status_code, ("error", HTTPStatus(status_code).phrase)
    )
    body: dict[str, object] = {
        "code": code or default_code,
        "message": message or default_message,
        "request_id": request_id_ctx.get(),
    }
    if details:
        body["details"] = details
    return JSONResponse({"error": body}, status_code=status_code, headers=headers)


async def _app_error_handler(_: Request, exc: AppError) -> JSONResponse:
    return error_response(exc.status_code, exc.code, exc.message)


async def _http_error_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    # Nur sicherheitsrelevante Header weiterreichen (z. B. Allow bei 405).
    passthrough = {k: v for k, v in (exc.headers or {}).items() if k.lower() in {"allow"}}
    return error_response(exc.status_code, headers=passthrough or None)


async def _validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        {
            "field": ".".join(str(part) for part in err.get("loc", ())),
            "type": str(err.get("type", "invalid")),
        }
        for err in exc.errors()
    ]
    return error_response(422, details=details)


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, _validation_error_handler)  # type: ignore[arg-type]
