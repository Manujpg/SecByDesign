"""Fachliche Tabellen gemäß docs/01-architektur.md, Abschnitt 7.

Integritätsregeln liegen bewusst (auch) in der Datenbank, nicht nur im Code:
- E-Mail-Adressen sind eindeutig und kleingeschrieben,
- ein Slot kann höchstens einen aktiven Termin haben (verhindert Doppelbuchungen
  auch bei gleichzeitigen Requests),
- Zeiträume und Längen sind per CHECK-Constraint begrenzt.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.enums import AppointmentStatus, AuditOutcome, InsuranceType, Role


def _enum(enum_cls: type, name: str) -> Enum:
    # Als VARCHAR + CHECK statt nativem PG-Enum: einfacher zu migrieren, gleich streng.
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=16,
        validate_strings=True,
        values_callable=lambda e: [m.value for m in e],
    )


class User(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(_enum(Role, "role"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # TOTP-Secret, AES-GCM-verschlüsselt (Nonce + Ciphertext), nie im Klartext.
    mfa_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary(128))
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint("failed_logins >= 0", name="failed_logins_nonneg"),
    )


class Patient(TimestampMixin, Base):
    __tablename__ = "patients"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    birth_date: Mapped[date] = mapped_column(Date, nullable=False)
    phone: Mapped[str | None] = mapped_column(String(32))
    insurance_type: Mapped[InsuranceType] = mapped_column(
        _enum(InsuranceType, "insurance_type"), nullable=False
    )

    __table_args__ = (Index("ix_patients_last_name_birth_date", "last_name", "birth_date"),)


class Doctor(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "doctors"

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), unique=True
    )
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str | None] = mapped_column(String(60))
    specialty: Mapped[str] = mapped_column(String(120), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Service(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "services"

    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    duration_min: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (CheckConstraint("duration_min BETWEEN 5 AND 240", name="duration_range"),)


class AvailabilitySlot(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "availability_slots"

    doctor_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("doctors.id", ondelete="CASCADE"), nullable=False
    )
    start_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_booked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        CheckConstraint("end_at > start_at", name="end_after_start"),
        UniqueConstraint("doctor_id", "start_at", name="uq_availability_slots_doctor_start"),
    )


class Appointment(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "appointments"

    patient_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("patients.user_id", ondelete="CASCADE"), nullable=False, index=True
    )
    doctor_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("doctors.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    service_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("services.id", ondelete="RESTRICT"), nullable=False
    )
    slot_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("availability_slots.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[AppointmentStatus] = mapped_column(
        _enum(AppointmentStatus, "appointment_status"),
        nullable=False,
        default=AppointmentStatus.BOOKED,
    )
    # Kurze Notiz ohne HTML; Länge zusätzlich in der DB begrenzt (SR-04, SR-13).
    note: Mapped[str | None] = mapped_column(String(200))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        # Höchstens ein aktiver Termin pro Slot - Schutz gegen Doppelbuchung (Race Condition).
        Index(
            "uq_appointments_active_slot",
            "slot_id",
            unique=True,
            postgresql_where=text("status = 'BOOKED'"),
            sqlite_where=text("status = 'BOOKED'"),
        ),
    )


class UserSession(UuidPkMixin, Base):
    """Serverseitige Sitzung. Gespeichert wird nur der SHA-256-Hash des Tokens."""

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32))


class RecoveryCode(UuidPkMixin, Base):
    __tablename__ = "recovery_codes"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    """Append-only Audit-Log (SR-11).

    Die Laufzeit-Rolle der Anwendung darf hier nur INSERT und SELECT (siehe Migration).
    ``actor_id`` ist bewusst kein Fremdschlüssel: Einträge bleiben unverändert, auch
    wenn ein Konto gelöscht wird.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(32))
    ip: Mapped[str | None] = mapped_column(String(45))
    outcome: Mapped[AuditOutcome] = mapped_column(
        _enum(AuditOutcome, "audit_outcome"), nullable=False
    )
