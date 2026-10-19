"""Endpunkte unter /api/v1/auth: Registrierung, Login, Logout, Identität, Passwortwechsel."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from app.api.deps import (
    SESSION_COOKIE,
    CurrentPrincipal,
    DbSession,
    LoggedIn,
    client_ip,
    user_agent,
)
from app.models import AuditOutcome, User
from app.schemas.auth import (
    LoginIn,
    LoginOut,
    MessageOut,
    PasswordChangeIn,
    RegisterIn,
    UserOut,
)
from app.services import audit
from app.services import auth as auth_service
from app.services.audit import Action
from app.services.mfa import mfa_required_for
from app.services.sessions import IssuedSession, resolve_session, revoke_session

router = APIRouter(prefix="/auth", tags=["auth"])


def set_session_cookie(response: Response, issued: IssuedSession) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        issued.token,
        max_age=issued.max_age_seconds,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")


def user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        role=user.role,
        mfa_enabled=user.mfa_enabled,
        mfa_setup_required=mfa_required_for(user) and not user.mfa_enabled,
        must_change_password=user.must_change_password,
    )


@router.post("/register", status_code=status.HTTP_202_ACCEPTED)
def register(body: RegisterIn, request: Request, db: DbSession) -> MessageOut:
    auth_service.register_patient(
        db,
        auth_service.PatientRegistration(
            email=str(body.email),
            password=body.password,
            first_name=body.first_name,
            last_name=body.last_name,
            birth_date=body.birth_date,
            phone=body.phone,
            insurance_type=body.insurance_type,
        ),
        ip=client_ip(request),
    )
    # Identische Antwort für "angelegt" und "E-Mail bereits vergeben" (keine Enumeration).
    return MessageOut(
        message="Vielen Dank. Wenn die Angaben gültig sind, können Sie sich jetzt anmelden."
    )


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: DbSession) -> LoginOut:
    # Eine evtl. vorhandene alte Sitzung beenden (Schutz vor Session Fixation).
    old = resolve_session(db, request.cookies.get(SESSION_COOKIE))
    if old is not None:
        revoke_session(db, old[0])

    result = auth_service.authenticate(
        db, body.email, body.password, ip=client_ip(request), user_agent=user_agent(request)
    )
    set_session_cookie(response, result.issued)
    return LoginOut(user=user_out(result.user), mfa_required=result.mfa_required)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, db: DbSession) -> Response:
    resolved = resolve_session(db, request.cookies.get(SESSION_COOKIE))
    if resolved is not None:
        session, user = resolved
        revoke_session(db, session)
        audit.record(
            db,
            Action.LOGOUT,
            AuditOutcome.SUCCESS,
            actor_id=user.id,
            target_type="user",
            target_id=str(user.id),
            ip=client_ip(request),
        )
    # Logout ist idempotent: Cookie wird in jedem Fall gelöscht.
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_session_cookie(response)
    return response


@router.get("/me")
def me(principal: LoggedIn) -> UserOut:
    return user_out(principal.user)


@router.post("/password")
def change_password(
    body: PasswordChangeIn,
    request: Request,
    response: Response,
    principal: LoggedIn,
    db: DbSession,
) -> UserOut:
    issued = auth_service.change_password(
        db,
        principal.user,
        body.current_password,
        body.new_password,
        mfa_verified=principal.session.mfa_verified,
        ip=client_ip(request),
        user_agent=user_agent(request),
    )
    set_session_cookie(response, issued)
    return user_out(principal.user)


@router.get("/session")
def session_state(principal: CurrentPrincipal) -> dict[str, bool]:
    """Minimaler Status für das Frontend (z. B. ob noch eine MFA-Eingabe aussteht)."""
    return {
        "mfa_required": not principal.session.mfa_verified,
        "must_change_password": principal.user.must_change_password,
        "mfa_setup_required": mfa_required_for(principal.user) and not principal.user.mfa_enabled,
    }
