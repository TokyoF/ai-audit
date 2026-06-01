import json
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.adapters.db.session import engine
from app.core.security import decode_access_token
from app.domain.agent.react_agent import ReactAgent
from app.domain.models.audit import Audit, AuditStatus
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

        agent = ReactAgent(session=session, audit=audit, target_host=target.host)

        try:
            agent_gen = agent.run()
            step = await agent_gen.__anext__()

            while True:
                await websocket.send_json({
                    "type": step.step_type,
                    "content": step.content,
                    "tool_used": step.tool_used,
                    "command_executed": step.command_executed,
                    "audit_status": audit.status.value,
                })

                if audit.status == AuditStatus.awaiting_decision:
                    decision_data = await websocket.receive_json()
                    decision = decision_data.get("decision", "continue")
                    try:
                        step = await agent_gen.asend(decision)
                    except StopAsyncIteration:
                        break
                else:
                    try:
                        step = await agent_gen.__anext__()
                    except StopAsyncIteration:
                        break

            await websocket.send_json({
                "type": "done",
                "content": "Audit completed",
                "audit_status": "idle",
            })

        except WebSocketDisconnect:
            audit.status = AuditStatus.idle
            session.add(audit)
            await session.commit()
        except Exception as e:
            await websocket.send_json({
                "type": "error",
                "content": str(e),
            })
        finally:
            try:
                await websocket.close()
            except Exception:
                pass
