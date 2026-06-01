import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime
from sqlmodel import Field, SQLModel


class StepType(str, Enum):
    thought = "thought"
    action = "action"
    observation = "observation"


class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_logs"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    audit_id: uuid.UUID = Field(foreign_key="audits.id", index=True)
    step_type: StepType
    content: str
    tool_used: str | None = Field(default=None)
    command_executed: str | None = Field(default=None)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime(timezone=True))
