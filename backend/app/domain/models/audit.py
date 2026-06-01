import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime
from sqlmodel import Field, SQLModel


class AuditStatus(str, Enum):
    scanning = "scanning"
    awaiting_decision = "awaiting_decision"
    exploiting = "exploiting"
    reporting = "reporting"
    idle = "idle"


class Audit(SQLModel, table=True):
    __tablename__ = "audits"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    target_id: uuid.UUID = Field(foreign_key="targets.id")
    status: AuditStatus = Field(default=AuditStatus.idle)
    started_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    finished_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    summary: str | None = Field(default=None)
    created_by: uuid.UUID = Field(foreign_key="users.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime(timezone=True))
