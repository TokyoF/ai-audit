import asyncio
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.adapters.db.session import engine
from app.core.security import decode_access_token
from app.domain.agent.react_agent import ReactAgent
from app.domain.models.audit import Audit, AuditStatus
from app.domain.models.audit_log import AuditLog, StepType
from app.domain.models.target import Target

router = APIRouter()


@router.websocket("/audits/{audit_id}/stream")
async def audit_stream(websocket: WebSocket, audit_id: str):
    await websocket.accept()

    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_json({"type": "error", "content": "Missing token"})
        await websocket.close()
        return

    user_id_str = decode_access_token(token)
    if not user_id_str:
        await websocket.send_json({"type": "error", "content": "Invalid token"})
        await websocket.close()
        return

    user_id = uuid.UUID(user_id_str)
    audit_uuid = uuid.UUID(audit_id)

    async with AsyncSession(engine) as session:
        result = await session.exec(
            select(Audit).where(Audit.id == audit_uuid, Audit.created_by == user_id)
        )
        audit = result.first()
        if not audit:
            await websocket.send_json({"type": "error", "content": "Audit not found"})
            await websocket.close()
            return

        target_result = await session.exec(
            select(Target).where(Target.id == audit.target_id)
        )
        target = target_result.first()
        target_host = target.host

        if audit.status == AuditStatus.idle:
            log_count_result = await session.exec(
                select(func.count()).select_from(AuditLog).where(AuditLog.audit_id == audit_uuid)
            )
            has_history = (log_count_result.first() or 0) > 0
            if has_history:
                # Explicit RESUME: a finished audit with prior history is
                # being reconnected to, so flip it back to scanning and let
                # the agent continue with new techniques instead of a blind rerun.
                audit.status = AuditStatus.scanning
                session.add(audit)
                await session.commit()

    agent = ReactAgent(audit_id=audit_uuid, target_host=target_host)

    # Capture optional initial operator context sent right after connect
    # ("Reanudar con contexto"). Normal "Iniciar agente" sends nothing, so
    # this times out quickly and we start fresh.
    try:
        first_msg = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
        mtype = first_msg.get("type")
        if mtype == "start":
            ctx = first_msg.get("context")
            if ctx:
                agent.resume_context = ctx
        elif mtype == "guidance":  # backward-compat
            ctx = first_msg.get("content", "")
            if ctx:
                agent.resume_context = ctx
    except asyncio.TimeoutError:
        first_msg = None

    async def run_agent():
        async with AsyncSession(engine) as agent_session:
            try:
                await agent.run(agent_session)
            except Exception as e:
                await agent.step_queue.put(
                    type("AgentStep", (), {"step_type": "error", "content": str(e), "tool_used": None, "command_executed": None})()
                )

    agent_task = asyncio.create_task(run_agent())

    try:
        while True:
            # Check for incoming messages (non-blocking)
            try:
                msg = await asyncio.wait_for(websocket.receive_json(), timeout=0.01)
                decision = msg.get("decision", "")
                if decision == "stop":
                    await agent.cancel()
                    await agent.send_decision("stop")
                    break
                elif decision in ("continue", "deeper", "skip"):
                    await agent.send_decision(decision)
                elif msg.get("type") == "guidance":
                    guidance_text = msg.get("content", "")
                    if guidance_text:
                        agent._history.append(f"USER: {guidance_text}")
                        try:
                            async with AsyncSession(engine) as gsession:
                                log = AuditLog(
                                    audit_id=audit_uuid,
                                    step_type=StepType.thought,
                                    content=f"📝 Auditor: {guidance_text}",
                                )
                                gsession.add(log)
                                await gsession.commit()
                        except Exception:
                            pass
                        if agent_task is None or agent_task.done():
                            # Agent had stopped/finished: restart it with the
                            # operator-supplied context instead of dropping
                            # the connection.
                            if hasattr(agent, "_cancel_event"):
                                agent._cancel_event.clear()
                            async with AsyncSession(engine) as guidance_session:
                                restart_audit = await guidance_session.get(Audit, audit_uuid)
                                if restart_audit:
                                    restart_audit.status = AuditStatus.scanning
                                    guidance_session.add(restart_audit)
                                    await guidance_session.commit()
                            agent_task = asyncio.create_task(run_agent())
                            await websocket.send_json({
                                "type": "thought",
                                "content": "Reanudando con el contexto del operador...",
                            })
            except asyncio.TimeoutError:
                pass
            except WebSocketDisconnect:
                await agent.cancel()
                break

            # Get next step from agent
            try:
                step = await asyncio.wait_for(agent.step_queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                if agent_task.done():
                    break
                continue

            await websocket.send_json({
                "type": step.step_type,
                "content": step.content,
                "tool_used": step.tool_used,
                "command_executed": step.command_executed,
                "audit_status": "awaiting_decision" if step.content == "Vulnerability detected. Waiting for auditor decision..." else ("idle" if step.step_type == "done" else "scanning"),
            })

            if step.step_type in ("done", "error"):
                break

            if step.content == "Vulnerability detected. Waiting for auditor decision...":
                try:
                    decision_data = await websocket.receive_json()
                    decision = decision_data.get("decision", "continue")
                    if decision == "stop":
                        await agent.cancel()
                    await agent.send_decision(decision)
                except WebSocketDisconnect:
                    await agent.send_decision("stop")
                    break

    except WebSocketDisconnect:
        await agent.send_decision("stop")
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "content": str(e)})
        except Exception:
            pass
    finally:
        if not agent_task.done():
            agent_task.cancel()
            try:
                await agent_task
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await websocket.close()
        except Exception:
            pass
