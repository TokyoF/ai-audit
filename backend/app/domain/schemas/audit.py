import uuid
from datetime import datetime

from pydantic import BaseModel

from app.domain.models.audit import AuditStatus
from app.domain.models.audit_log import StepType
from app.domain.models.vulnerability import Severity


class CreateAuditRequest(BaseModel):
    host: str
    description: str | None = None


class AuditResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    status: AuditStatus
    started_at: datetime | None
    finished_at: datetime | None
    summary: str | None
    created_by: uuid.UUID
    created_at: datetime


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    step_type: StepType
    content: str
    tool_used: str | None
    command_executed: str | None
    timestamp: datetime


class VulnerabilityResponse(BaseModel):
    id: uuid.UUID
    audit_id: uuid.UUID
    title: str
    cve_id: str | None
    cvss_score: float | None
    severity: Severity
    description: str
    poc: str | None
    remediation: str | None
    discovered_at: datetime


class FindingsResponse(BaseModel):
    audit_id: uuid.UUID
    status: AuditStatus
    vulnerabilities: list[VulnerabilityResponse]
    logs: list[AuditLogResponse]
