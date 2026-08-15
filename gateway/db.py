"""Persistence.

SQLite via SQLAlchemy, which keeps migration overhead at zero. Postgres is a
roadmap item; nothing here depends on the storage engine beyond this module.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .settings import DB_URL


class Base(DeclarativeBase):
    pass


class SessionRow(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    goal: Mapped[str] = mapped_column(Text, default="")
    scenario: Mapped[str] = mapped_column(String(120), default="")
    kind: Mapped[str] = mapped_column(String(16), default="benign")  # benign | attack
    enforced: Mapped[bool] = mapped_column(Boolean, default=True)
    trust: Mapped[int] = mapped_column(Integer, default=100)
    started_at: Mapped[float] = mapped_column(Float, default=time.time)
    ended_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), default="running")


class ToolCallRow(Base):
    __tablename__ = "tool_calls"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), ForeignKey("sessions.id"), index=True)
    idx: Mapped[int] = mapped_column(Integer)
    tool: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    justification: Mapped[str] = mapped_column(Text, default="")
    derived_from: Mapped[list[str]] = mapped_column(JSON, default=list)
    decision: Mapped[str] = mapped_column(String(16))
    caught_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    ring_results: Mapped[list[dict]] = mapped_column(JSON, default=list)
    trust_after: Mapped[int] = mapped_column(Integer, default=100)
    executed: Mapped[bool] = mapped_column(Boolean, default=False)
    enforced: Mapped[bool] = mapped_column(Boolean, default=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    ts: Mapped[float] = mapped_column(Float, default=time.time)


class LedgerRow(Base):
    """Append-only, hash-chained.

    Nothing in the application ever updates or deletes a row here. `/verify`
    re-walks the chain, so editing a row directly in SQLite is detectable
    rather than merely discouraged.
    """

    __tablename__ = "ledger"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    ts: Mapped[float] = mapped_column(Float, default=time.time)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


_engine = create_engine(
    DB_URL, future=True, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)


def engine():
    return _engine


def init_db(drop: bool = False) -> None:
    if drop:
        Base.metadata.drop_all(_engine)
    Base.metadata.create_all(_engine)


def reset_db() -> None:
    init_db(drop=True)
