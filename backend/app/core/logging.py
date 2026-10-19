"""Strukturiertes JSON-Logging mit Request-ID.

Grundsatz: Logs enthalten keine Passwörter, Tokens, Query-Strings oder
Gesundheitsdaten. Der Zugriffslog schreibt nur Methode, Pfad, Status und Dauer.
"""

from __future__ import annotations

import json
import logging
from contextvars import ContextVar
from datetime import UTC, datetime

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)


class JsonFormatter(logging.Formatter):
    _EXTRA_FIELDS = ("method", "path", "status", "duration_ms", "event")

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        request_id = request_id_ctx.get()
        if request_id:
            payload["request_id"] = request_id
        for field in self._EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            # Stacktraces landen nur im Server-Log, nie in der HTTP-Antwort (SR-05).
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # uvicorn-Logger auf dasselbe Format umleiten; den eigenen Access-Log von
    # uvicorn ersetzen wir durch den der Middleware (ohne Query-Strings).
    for name in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False
    logging.getLogger("uvicorn.access").disabled = True
