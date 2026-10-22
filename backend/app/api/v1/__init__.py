"""Versionierte REST-API unter /api/v1.

Fachliche Router (auth, appointments, staff, doctor, admin) kommen in den
Paketen M3, M5, L8 und L9 hinzu und werden hier registriert.
"""

from fastapi import APIRouter

from app.api import health
from app.api.v1 import auth, mfa

api_router = APIRouter()

# Health auch unter /api/v1, damit der Smoke-Test über den Ingress (/api → Backend) prüfen kann.
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(mfa.router)
