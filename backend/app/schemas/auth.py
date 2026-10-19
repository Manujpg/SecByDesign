"""Ein- und Ausgabe-Schemas für /api/v1/auth (SR-04).

Alle Eingaben haben harte Längen- und Formatgrenzen. Passwörter werden nie
getrimmt oder normalisiert, sondern exakt so gehasht, wie sie eingegeben wurden.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Annotated

from pydantic import BaseModel, EmailStr, StringConstraints, field_validator

from app.core.security import PASSWORD_MAX_LENGTH
from app.core.timeutil import utcnow
from app.models import InsuranceType, Role
from app.schemas.base import StrictModel

# Buchstaben aller Sprachen, Leerzeichen, Punkt, Bindestrich, Apostroph (z. B. "Anne-Marie O'Neil").
NameStr = Annotated[
    str, StringConstraints(min_length=1, max_length=100, pattern=r"^\p{L}[\p{L} .'\-]*$")
]
PhoneStr = Annotated[str, StringConstraints(max_length=32, pattern=r"^\+?[0-9][0-9 ()/\-]{4,30}$")]
# Passwörter: nicht trimmen; Obergrenze schützt vor teurem Hashing riesiger Eingaben.
PasswordStr = Annotated[
    str, StringConstraints(min_length=1, max_length=PASSWORD_MAX_LENGTH, strip_whitespace=False)
]
LoginEmailStr = Annotated[str, StringConstraints(min_length=3, max_length=254)]


class RegisterIn(StrictModel):
    email: Annotated[EmailStr, StringConstraints(max_length=254)]
    password: PasswordStr
    first_name: NameStr
    last_name: NameStr
    birth_date: date
    phone: PhoneStr | None = None
    insurance_type: InsuranceType

    @field_validator("birth_date")
    @classmethod
    def _plausible_birth_date(cls, value: date) -> date:
        if not date(1900, 1, 1) <= value <= utcnow().date():
            raise ValueError("Geburtsdatum außerhalb des gültigen Bereichs")
        return value


class LoginIn(StrictModel):
    email: LoginEmailStr
    password: PasswordStr


class PasswordChangeIn(StrictModel):
    current_password: PasswordStr
    new_password: PasswordStr


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    role: Role
    mfa_enabled: bool
    mfa_setup_required: bool
    must_change_password: bool


class LoginOut(BaseModel):
    user: UserOut
    mfa_required: bool


class MessageOut(BaseModel):
    message: str
