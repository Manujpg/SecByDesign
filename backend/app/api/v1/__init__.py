"""Versionierte REST-API unter /api/v1.

Fachliche Router (auth, appointments, staff, doctor, admin) kommen in den
Paketen M3, M5, L8 und L9 hinzu und werden hier registriert.
"""

from fastapi import APIRouter

from app.api import health

api_router = APIRouter()

# Health auch unter /api/v1, damit der Smoke-Test über den Ingress (/api → Backend) prüfen kann.
api_router.include_router(health.router)
