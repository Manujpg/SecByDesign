"""Integritätsregeln des Datenmodells, die in der Datenbank erzwungen werden."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from app.models import (
    Appointment,
    AppointmentStatus,
    AvailabilitySlot,
    Doctor,
    InsuranceType,
    Patient,
    Role,
    Service,
    User,
)


def _user(email: str = "anna@example.org", role: Role = Role.PATIENT) -> User:
    return User(email=email, password_hash="$argon2id$platzhalter", role=role)


@pytest.fixture
def booking_setup(db: Session):
    user = _user()
    db.add(user)
    db.flush()
    patient = Patient(
        user_id=user.id,
        first_name="Anna",
        last_name="Muster",
        birth_date=date(1990, 1, 1),
        insurance_type=InsuranceType.GKV,
    )
    doctor = Doctor(display_name="Dr. Lindle", specialty="Allgemeinmedizin")
    service = Service(name="Hausarztsprechstunde", duration_min=15)
    db.add_all([patient, doctor, service])
    db.flush()
    start = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
    slot = AvailabilitySlot(
        doctor_id=doctor.id, start_at=start, end_at=start + timedelta(minutes=15)
    )
    db.add(slot)
    db.flush()
    return patient, doctor, service, slot


def _appointment(patient, doctor, service, slot, status=AppointmentStatus.BOOKED) -> Appointment:
    return Appointment(
        patient_id=patient.user_id,
        doctor_id=doctor.id,
        service_id=service.id,
        slot_id=slot.id,
        status=status,
    )


def test_email_must_be_unique(db: Session) -> None:
    db.add_all([_user(), _user()])
    with pytest.raises(IntegrityError):
        db.flush()


def test_email_must_be_lowercase(db: Session) -> None:
    db.add(_user(email="Anna@Example.org"))
    with pytest.raises(IntegrityError):
        db.flush()


def test_invalid_role_rejected(db: Session) -> None:
    db.add(User(email="x@example.org", password_hash="h", role="SUPERUSER"))
    with pytest.raises((StatementError, LookupError)):
        db.flush()


def test_slot_cannot_be_double_booked(db: Session, booking_setup) -> None:
    db.add(_appointment(*booking_setup))
    db.flush()
    db.add(_appointment(*booking_setup))
    with pytest.raises(IntegrityError):
        db.flush()


def test_slot_can_be_rebooked_after_cancellation(db: Session, booking_setup) -> None:
    db.add(_appointment(*booking_setup, status=AppointmentStatus.CANCELLED))
    db.flush()
    db.add(_appointment(*booking_setup))
    db.flush()  # kein Fehler


def test_slot_end_must_be_after_start(db: Session, booking_setup) -> None:
    _, doctor, _, _ = booking_setup
    start = datetime(2026, 11, 3, 9, 0, tzinfo=UTC)
    db.add(AvailabilitySlot(doctor_id=doctor.id, start_at=start, end_at=start))
    with pytest.raises(IntegrityError):
        db.flush()


def test_service_duration_range(db: Session) -> None:
    db.add(Service(name="Unsinn", duration_min=1000))
    with pytest.raises(IntegrityError):
        db.flush()


def test_note_length_limited_in_db(db: Session, booking_setup) -> None:
    appt = _appointment(*booking_setup)
    appt.note = "x" * 200
    db.add(appt)
    db.flush()  # genau 200 Zeichen sind erlaubt
    assert Appointment.__table__.c.note.type.length == 200
