"""Aufzählungstypen des Fachmodells."""

from __future__ import annotations

import enum


class Role(enum.StrEnum):
    PATIENT = "PATIENT"
    STAFF = "STAFF"
    DOCTOR = "DOCTOR"
    ADMIN = "ADMIN"


class InsuranceType(enum.StrEnum):
    GKV = "GKV"
    PKV = "PKV"
    SELBSTZAHLER = "SELBSTZAHLER"


class AppointmentStatus(enum.StrEnum):
    BOOKED = "BOOKED"
    CANCELLED = "CANCELLED"
    DONE = "DONE"
    NO_SHOW = "NO_SHOW"


class AuditOutcome(enum.StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
