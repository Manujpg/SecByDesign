"""Endpunkte unter /api/v1/auth/mfa: Einrichtung, Bestätigung beim Login, Verwaltung."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from app.api.deps import (
    ActiveUser,
    CurrentPrincipal,
    DbSession,
    PasswordCurrent,
    client_ip,
    user_agent,
)
from app.api.v1.auth import set_session_cookie, user_out
from app.schemas.auth import UserOut
from app.schemas.mfa import (
    MfaCodeIn,
    MfaDisableIn,
    MfaSetupOut,
    MfaVerifyIn,
    RecoveryCodesOut,
)
from app.services import mfa as mfa_service

router = APIRouter(prefix="/auth/mfa", tags=["mfa"])


@router.post("/setup")
def setup(request: Request, principal: PasswordCurrent, db: DbSession) -> MfaSetupOut:
    """Erzeugt ein neues TOTP-Secret. Das Frontend zeigt die URI als QR-Code an."""
    data = mfa_service.start_setup(db, principal.user, ip=client_ip(request))
    return MfaSetupOut(secret=data.secret, otpauth_uri=data.otpauth_uri)


@router.post("/confirm")
def confirm(
    body: MfaCodeIn,
    request: Request,
    response: Response,
    principal: PasswordCurrent,
    db: DbSession,
) -> RecoveryCodesOut:
    """Aktiviert MFA mit dem ersten Code und gibt die Recovery-Codes genau einmal aus."""
    codes, issued = mfa_service.confirm_setup(
        db, principal.user, body.code, ip=client_ip(request), user_agent=user_agent(request)
    )
    set_session_cookie(response, issued)
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/verify")
def verify(
    body: MfaVerifyIn,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    db: DbSession,
) -> UserOut:
    """Zweiter Schritt der Anmeldung: Code aus der App oder ein Recovery-Code."""
    issued = mfa_service.verify_login(
        db,
        principal.user,
        principal.session,
        code=body.code,
        recovery_code=body.recovery_code,
        ip=client_ip(request),
        user_agent=user_agent(request),
    )
    set_session_cookie(response, issued)
    return user_out(principal.user)


@router.post("/recovery-codes")
def regenerate_recovery_codes(
    body: MfaCodeIn, request: Request, principal: ActiveUser, db: DbSession
) -> RecoveryCodesOut:
    """Neue Recovery-Codes; alle bisherigen werden ungültig."""
    codes = mfa_service.regenerate_recovery_codes(
        db, principal.user, body.code, ip=client_ip(request)
    )
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable(body: MfaDisableIn, request: Request, principal: ActiveUser, db: DbSession) -> Response:
    """Nur für Patient:innen; verlangt Passwort und aktuellen Code."""
    mfa_service.disable(
        db,
        principal.user,
        principal.session,
        password=body.password,
        code=body.code,
        ip=client_ip(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
