"""Zugriffs-Abhängigkeiten für Router (SR-01, SR-03, SR-07).

Jede geschützte Route hängt von genau einer dieser Stufen ab:

    get_principal              gültige Sitzung (auch wenn MFA noch offen ist) - Logout, MFA-Code
    require_login              Sitzung inkl. abgeschlossener MFA - /auth/me, Passwortwechsel
    require_password_current   zusätzlich kein offener Pflicht-Passwortwechsel - MFA-Einrichtung
    require_active_user        zusätzlich MFA aktiv, falls die Rolle sie verlangt - Fachfunktionen
    require_roles(...)         zusätzlich eine der genannten Rollen

Reihenfolge beim ersten Admin-Login: Initialpasswort ändern -> MFA einrichten -> Zugriff.
Die Prüfungen laufen ausschließlich serverseitig; das Frontend blendet nur aus.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db import get_db
from app.models import Role, User, UserSession
from app.services.mfa import mfa_required_for
from app.services.sessions import resolve_session

# __Host-Präfix: Browser akzeptieren das Cookie nur mit Secure, Path=/ und ohne Domain.
SESSION_COOKIE = "__Host-session"

DbSession = Annotated[Session, Depends(get_db)]


@dataclass(frozen=True)
class Principal:
    user: User
    session: UserSession


def client_ip(request: Request) -> str | None:
    # Hinter dem Ingress liefert uvicorn (--proxy-headers, FORWARDED_ALLOW_IPS) die echte Client-IP.
    return request.client.host if request.client else None


def user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent")


def get_principal(request: Request, db: DbSession) -> Principal:
    resolved = resolve_session(db, request.cookies.get(SESSION_COOKIE))
    if resolved is None:
        raise AppError(401, "not_authenticated", "Bitte melden Sie sich an.")
    session, user = resolved
    return Principal(user=user, session=session)


def require_login(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
    if not principal.session.mfa_verified:
        raise AppError(401, "mfa_required", "Bitte bestätigen Sie die Anmeldung mit Ihrem Code.")
    return principal


def require_password_current(
    principal: Annotated[Principal, Depends(require_login)],
) -> Principal:
    if principal.user.must_change_password:
        raise AppError(
            403, "password_change_required", "Bitte ändern Sie zuerst Ihr Initialpasswort."
        )
    return principal


def require_active_user(
    principal: Annotated[Principal, Depends(require_password_current)],
) -> Principal:
    # SR-02: Praxispersonal, Ärzt:innen und Admins kommen ohne aktive MFA an keine Fachfunktion.
    if mfa_required_for(principal.user) and not principal.user.mfa_enabled:
        raise AppError(
            403, "mfa_setup_required", "Bitte richten Sie zuerst die Zwei-Faktor-Anmeldung ein."
        )
    return principal


def require_roles(*roles: Role) -> Callable[[Principal], Principal]:
    allowed = frozenset(roles)

    def _check(principal: Annotated[Principal, Depends(require_active_user)]) -> Principal:
        if principal.user.role not in allowed:
            raise AppError(403, "forbidden", "Für diese Aktion fehlt die Berechtigung.")
        return principal

    return _check


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
LoggedIn = Annotated[Principal, Depends(require_login)]
PasswordCurrent = Annotated[Principal, Depends(require_password_current)]
ActiveUser = Annotated[Principal, Depends(require_active_user)]
