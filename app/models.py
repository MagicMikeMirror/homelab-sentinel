from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(80), default="generic", index=True)
    status: Mapped[str] = mapped_column(String(30), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    events: Mapped[list["SecurityEvent"]] = relationship(back_populates="source")


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_seen_at_severity", "seen_at", "severity"),
        Index("ix_security_events_source_ip", "source_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[str] = mapped_column(String(30), index=True)
    title: Mapped[str] = mapped_column(String(255))
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    scenario: Mapped[str | None] = mapped_column(String(255), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    source: Mapped[Source] = relationship(back_populates="events")
