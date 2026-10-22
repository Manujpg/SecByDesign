"""Schemas für /api/v1/auth/mfa (SR-02, SR-04)."""

from __future__ import annotations

from typing import Annotated, Self

from pydantic import BaseModel, StringConstraints, model_validator

from app.schemas.auth import PasswordStr
from app.schemas.base import StrictModel

TotpCode = Annotated[str, StringConstraints(pattern=r"^[0-9]{6}$")]
# Format "abcde-fghij"; Groß-/Kleinschreibung und Bindestrich sind beim Abtippen egal.
RecoveryCodeStr = Annotated[
    str, StringConstraints(max_length=16, pattern=r"^(?i)[a-z0-9]{5}[- ]?[a-z0-9]{5}$")
]


class MfaCodeIn(StrictModel):
    code: TotpCode


class MfaVerifyIn(StrictModel):
    code: TotpCode | None = None
    recovery_code: RecoveryCodeStr | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        if (self.code is None) == (self.recovery_code is None):
            raise ValueError("Genau eines von code oder recovery_code angeben")
        return self


class MfaDisableIn(StrictModel):
    password: PasswordStr
    code: TotpCode


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]
