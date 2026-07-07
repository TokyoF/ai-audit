import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import delete, func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.adapters.db.session import get_session
from app.core.dependencies import get_current_user
from app.domain.models.audit import Audit, AuditStatus
from app.domain.models.audit_log import AuditLog
from app.domain.models.target import Target
from app.domain.models.user import User
from app.domain.models.vulnerability import Vulnerability
from app.domain.agent.recon_parser import parse_open_ports, suggest_attacks
from app.domain.schemas.audit import (
    AuditListItem,
    AuditLogResponse,
    AuditResponse,
    CreateAuditRequest,
    FindingsResponse,
    UpdateStatusRequest,
    VulnerabilityResponse,
)

router = APIRouter(prefix="/audits", tags=["audits"])


@router.post("", response_model=AuditResponse, status_code=status.HTTP_201_CREATED)
async def create_audit(
    body: CreateAuditRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    target = Target(
        host=body.host.strip(),
        description=body.description,
        is_authorized=True,
        created_by=current_user.id,
    )
    session.add(target)
    await session.flush()

    audit = Audit(
        target_id=target.id,
        status=AuditStatus.pending,
        started_at=datetime.now(timezone.utc),
        created_by=current_user.id,
    )
    session.add(audit)
    await session.commit()
    await session.refresh(audit)
    return audit


@router.get("", response_model=list[AuditListItem])
async def list_audits(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    result = await session.exec(
        select(Audit).where(Audit.created_by == current_user.id).order_by(Audit.created_at.desc())
    )
    audits = result.all()
    if not audits:
        return []

    target_ids = {audit.target_id for audit in audits}
    audit_ids = [audit.id for audit in audits]

    targets_result = await session.exec(select(Target).where(Target.id.in_(target_ids)))
    host_by_target_id = {target.id: target.host for target in targets_result.all()}

    counts_result = await session.exec(
        select(Vulnerability.audit_id, func.count())
        .where(Vulnerability.audit_id.in_(audit_ids))
        .group_by(Vulnerability.audit_id)
    )
    vuln_count_by_audit_id = {audit_id: count for audit_id, count in counts_result.all()}

    return [
        AuditListItem(
            id=audit.id,
            target_id=audit.target_id,
            status=audit.status,
            started_at=audit.started_at,
            finished_at=audit.finished_at,
            summary=audit.summary,
            created_by=audit.created_by,
            created_at=audit.created_at,
            host=host_by_target_id.get(audit.target_id),
            vuln_count=vuln_count_by_audit_id.get(audit.id, 0),
        )
        for audit in audits
    ]


@router.get("/{audit_id}", response_model=AuditResponse)
async def get_audit(
    audit_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    result = await session.exec(
        select(Audit).where(Audit.id == audit_id, Audit.created_by == current_user.id)
    )
    audit = result.first()
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
    return audit


@router.post("/{audit_id}/continue", response_model=AuditResponse)
async def continue_audit(
    audit_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    audit = await _get_user_audit(audit_id, current_user.id, session)
    if audit.status != AuditStatus.awaiting_decision:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Audit is not awaiting decision")
    audit.status = AuditStatus.scanning
    session.add(audit)
    await session.commit()
    await session.refresh(audit)
    return audit


@router.post("/{audit_id}/deeper", response_model=AuditResponse)
async def deeper_audit(
    audit_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    audit = await _get_user_audit(audit_id, current_user.id, session)
    if audit.status != AuditStatus.awaiting_decision:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Audit is not awaiting decision")
    audit.status = AuditStatus.exploiting
    session.add(audit)
    await session.commit()
    await session.refresh(audit)
    return audit


@router.post("/{audit_id}/skip", response_model=AuditResponse)
async def skip_finding(
    audit_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    audit = await _get_user_audit(audit_id, current_user.id, session)
    if audit.status != AuditStatus.awaiting_decision:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Audit is not awaiting decision")
    audit.status = AuditStatus.scanning
    session.add(audit)
    await session.commit()
    await session.refresh(audit)
    return audit


@router.post("/{audit_id}/stop", response_model=AuditResponse)
async def stop_audit(
    audit_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    audit = await _get_user_audit(audit_id, current_user.id, session)
    if audit.status == AuditStatus.idle:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Audit already stopped")
    audit.status = AuditStatus.idle
    audit.finished_at = datetime.now(timezone.utc)
    session.add(audit)
    await session.commit()
    await session.refresh(audit)
    return audit


@router.get("/{audit_id}/findings", response_model=FindingsResponse)
async def get_findings(
    audit_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    audit = await _get_user_audit(audit_id, current_user.id, session)
    vulns = await session.exec(
        select(Vulnerability).where(Vulnerability.audit_id == audit_id).order_by(Vulnerability.discovered_at.desc())
    )
    logs = await session.exec(
        select(AuditLog).where(AuditLog.audit_id == audit_id).order_by(AuditLog.timestamp.asc())
    )
    log_rows = logs.all()
    open_ports = parse_open_ports(log_rows)
    suggested_attacks = suggest_attacks(open_ports)
    return FindingsResponse(
        audit_id=audit.id,
        status=audit.status,
        vulnerabilities=vulns.all(),
        logs=log_rows,
        open_ports=open_ports,
        suggested_attacks=suggested_attacks,
    )


@router.delete("/{audit_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_audit(
    audit_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    audit = await _get_user_audit(audit_id, current_user.id, session)

    await session.execute(delete(Vulnerability).where(Vulnerability.audit_id == audit.id))
    await session.execute(delete(AuditLog).where(AuditLog.audit_id == audit.id))
    await session.execute(delete(Audit).where(Audit.id == audit.id))
    await session.execute(delete(Target).where(Target.id == audit.target_id))
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


_USER_SETTABLE_STATUSES = {AuditStatus.pending, AuditStatus.scanning, AuditStatus.completed}


@router.patch("/{audit_id}/status", response_model=AuditResponse)
async def update_audit_status(
    audit_id: uuid.UUID,
    body: UpdateStatusRequest,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if body.status not in _USER_SETTABLE_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")

    audit = await _get_user_audit(audit_id, current_user.id, session)
    audit.status = body.status
    if body.status == AuditStatus.completed:
        audit.finished_at = datetime.now(timezone.utc)
    session.add(audit)
    await session.commit()
    await session.refresh(audit)
    return audit


async def _get_user_audit(audit_id: uuid.UUID, user_id: uuid.UUID, session: AsyncSession) -> Audit:
    result = await session.exec(
        select(Audit).where(Audit.id == audit_id, Audit.created_by == user_id)
    )
    audit = result.first()
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
    return audit
