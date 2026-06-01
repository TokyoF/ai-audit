import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlmodel import Field, SQLModel


class Target(SQLModel, table=True):
    __tablename__ = "targets"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    host: str = Field(max_length=255, index=True)
    description: str | None = Field(default=None)
    is_authorized: bool = Field(default=False)
    created_by: uuid.UUID = Field(foreign_key="users.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime(timezone=True))
