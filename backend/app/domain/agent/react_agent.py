import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.adapters.ai.ollama_client import ollama_client
from app.adapters.tools import AVAILABLE_TOOLS
from app.adapters.tools.base import ToolResult
from app.domain.models.audit import Audit, AuditStatus
from app.domain.models.audit_log import AuditLog, StepType
from app.domain.models.vulnerability import Severity, Vulnerability


SYSTEM_PROMPT = """You are an expert cybersecurity penetration tester AI agent. You perform security audits by analyzing targets using available tools.

Available tools:
- nmap: Port scanner. Parameters: target (required), scan_type (basic|full|udp|vuln, default: basic)
- hydra: Brute force tool. Parameters: target (required), service (ssh|ftp|http, default: ssh), username (default: admin)
- sqlmap: SQL injection scanner. Parameters: url (required), forms (bool), crawl (bool)

You MUST respond in this exact format every time:

THOUGHT: <your reasoning about what to do next>
ACTION: <tool_name>
PARAMS: <json parameters>

OR if you found a vulnerability:

THOUGHT: <your analysis of the finding>
FINDING: <vulnerability title>
SEVERITY: <critical|high|medium|low|info>
CVSS: <score 0.0-10.0>
DESCRIPTION: <detailed description>
REMEDIATION: <how to fix it>

OR if the scan is complete:

THOUGHT: <summary reasoning>
DONE: <final summary of the audit>

Rules:
- Always start with an nmap basic scan to discover open ports
- Analyze each result before deciding the next action
- Report every vulnerability you find as a FINDING
- Be thorough but efficient
- Never run destructive commands

Diversification rules:
- Do NOT repeat an identical ACTION with identical PARAMS. If a scan already ran, choose a DIFFERENT tool or a different nmap scan_type.
- Escalate nmap scans progressively: start with basic, then full (all ports), then vuln (NSE vuln scripts), and udp when relevant. Use each scan_type at most once unless new information justifies it.
- After enumeration, pivot to service-specific tools: hydra for exposed auth services (ssh/ftp/http), sqlmap for web apps with parameters.
- Only respond DONE when you have tried multiple distinct techniques and no further useful action remains. Do not declare DONE just because one scan finished.
"""


@dataclass
class AgentStep:
    step_type: str
    content: str
    tool_used: str | None = None
    command_executed: str | None = None


@dataclass
class ReactAgent:
    audit_id: str
    target_host: str
    step_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    decision_event: asyncio.Event = field(default_factory=asyncio.Event)
    decision_value: str = "continue"
    is_running: bool = False
    _history: list[str] = field(default_factory=list)
    _failed_tools: set = field(default_factory=set)
    _executed_actions: set = field(default_factory=set)
    _cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    max_steps: int = 20

    async def run(self, session: AsyncSession) -> None:
        self.is_running = True

        audit = await session.get(Audit, self.audit_id)
        audit.status = AuditStatus.scanning
        session.add(audit)
        await session.commit()

        await self._load_history(session)

        if self._history:
            self._history.append("USER: Resume this audit. Review what was already tried above and continue with a NEW technique or tool that has NOT been used yet. Do NOT respond DONE unless you have genuinely exhausted distinct approaches.")
        else:
            initial_prompt = f"Begin a security audit on target: {self.target_host}\nStart with reconnaissance."
            self._history.append(f"USER: {initial_prompt}")

        try:
            for _ in range(self.max_steps):
                if self._cancel_event.is_set():
                    break
                prompt = "\n".join(self._history)

                await self._emit(AgentStep(step_type="thought", content="Thinking..."))

                response = await ollama_client.generate(prompt=prompt, system=SYSTEM_PROMPT)
                self._history.append(f"ASSISTANT: {response}")

                parsed = self._parse_response(response)

                if parsed["type"] == "action":
                    await self._emit(AgentStep(step_type="thought", content=parsed["thought"]))
                    await self._log_step(session, "thought", parsed["thought"])

                    action_key = f"{parsed['tool']}:{json.dumps(parsed['params'], sort_keys=True)}"
                    if action_key in self._executed_actions:
                        duplicate_msg = (
                            f"You already executed '{parsed['tool']}' with these exact parameters. "
                            "Do NOT repeat it. Choose a different tool or a different nmap scan_type."
                        )
                        await self._emit(AgentStep(step_type="observation", content=duplicate_msg))
                        await self._log_step(session, "observation", duplicate_msg)
                        self._history.append(f"OBSERVATION: {duplicate_msg}")
                        continue
                    self._executed_actions.add(action_key)

                    tool_result = await self._execute_tool(parsed["tool"], parsed["params"])

                    await self._emit(AgentStep(
                        step_type="action",
                        content=f"Executing {parsed['tool']}",
                        tool_used=parsed["tool"],
                        command_executed=tool_result.command,
                    ))
                    await self._log_step(session, "action", f"Executing {parsed['tool']}", parsed["tool"], tool_result.command)

                    is_env_error = tool_result.output.strip().startswith("ENV_ERROR:")

                    if is_env_error:
                        observation = (
                            "Entorno no disponible: el contenedor de herramientas (aiaudit-tools) "
                            "o Docker no responde. Verifica que el contenedor esté corriendo."
                        )
                    else:
                        observation = tool_result.output[:3000]

                    await self._emit(AgentStep(step_type="observation", content=observation))
                    await self._log_step(session, "observation", observation)

                    if is_env_error:
                        self._history.append(f"OBSERVATION: {observation}")
                    elif not tool_result.success and "not found" in tool_result.output.lower():
                        self._failed_tools.add(parsed["tool"])
                        available = [t for t in AVAILABLE_TOOLS if t not in self._failed_tools]
                        if not available:
                            self._history.append(f"OBSERVATION: {observation}\nUSER: All tools are unavailable. End the audit with a DONE response summarizing what happened.")
                        else:
                            self._history.append(f"OBSERVATION: {observation}\nUSER: The tool '{parsed['tool']}' is not installed and unavailable. Do NOT try it again. Available tools: {available}. If no tools can help, respond with DONE.")
                    else:
                        self._history.append(f"OBSERVATION: {observation}")

                elif parsed["type"] == "finding":
                    await self._emit(AgentStep(step_type="thought", content=parsed["thought"]))
                    await self._log_step(session, "thought", parsed["thought"])

                    await self._save_vulnerability(session, parsed)

                    finding_msg = f"VULNERABILITY FOUND: [{parsed['severity'].upper()}] {parsed['title']}\n{parsed['description']}"
                    await self._emit(AgentStep(step_type="observation", content=finding_msg))
                    await self._log_step(session, "observation", finding_msg)

                    audit = await session.get(Audit, self.audit_id)
                    audit.status = AuditStatus.awaiting_decision
                    session.add(audit)
                    await session.commit()

                    await self._emit(AgentStep(
                        step_type="thought",
                        content="Vulnerability detected. Waiting for auditor decision...",
                    ))

                    self.decision_event.clear()
                    await self.decision_event.wait()
                    decision = self.decision_value

                    audit = await session.get(Audit, self.audit_id)

                    if decision == "stop":
                        break
                    elif decision == "deeper":
                        audit.status = AuditStatus.exploiting
                        session.add(audit)
                        await session.commit()
                        self._history.append(f"USER: Investigate this vulnerability deeper: {parsed['title']}")
                    elif decision == "skip":
                        audit.status = AuditStatus.scanning
                        session.add(audit)
                        await session.commit()
                        self._history.append("USER: Skip this finding and continue scanning.")
                    else:
                        audit.status = AuditStatus.scanning
                        session.add(audit)
                        await session.commit()
                        self._history.append("USER: Continue scanning for more vulnerabilities.")

                elif parsed["type"] == "done":
                    await self._emit(AgentStep(step_type="thought", content=parsed["summary"]))
                    await self._log_step(session, "thought", parsed["summary"])
                    break

                else:
                    await self._emit(AgentStep(step_type="thought", content=response[:500]))
                    await self._log_step(session, "thought", response[:500])
                    self._history.append("USER: Please follow the required response format. Continue the audit.")

        finally:
            audit = await session.get(Audit, self.audit_id)
            audit.status = AuditStatus.idle
            audit.finished_at = datetime.now(timezone.utc)
            session.add(audit)
            await session.commit()
            self.is_running = False

            await self._emit(AgentStep(step_type="done", content="Audit completed"))

    async def cancel(self) -> None:
        self._cancel_event.set()

    async def send_decision(self, decision: str) -> None:
        self.decision_value = decision
        self.decision_event.set()

    async def _load_history(self, session: AsyncSession) -> None:
        result = await session.exec(
            select(AuditLog)
            .where(AuditLog.audit_id == self.audit_id)
            .order_by(AuditLog.timestamp.asc())
        )
        logs = result.all()
        if not logs:
            return
        for log in logs:
            if log.step_type == StepType.thought:
                self._history.append(f"ASSISTANT: THOUGHT: {log.content}")
            elif log.step_type == StepType.action:
                if log.command_executed:
                    self._history.append(f"ASSISTANT: ACTION: {log.tool_used}\nPARAMS: (executed as: {log.command_executed})")
                else:
                    self._history.append(f"ASSISTANT: ACTION: {log.tool_used}")
                action_key = f"{log.tool_used}:{log.command_executed or '{}'}"
                self._executed_actions.add(action_key)
            elif log.step_type == StepType.observation:
                self._history.append(f"OBSERVATION: {log.content}")

    async def _emit(self, step: AgentStep) -> None:
        await self.step_queue.put(step)

    def _parse_response(self, response: str) -> dict:
        response = response.strip()

        if "ACTION:" in response:
            thought = self._extract(response, "THOUGHT:")
            tool = self._extract(response, "ACTION:").strip().lower()
            params_str = self._extract(response, "PARAMS:")
            try:
                params = json.loads(params_str)
            except (json.JSONDecodeError, TypeError):
                params = {"target": self.target_host}
            if "target" not in params and "url" not in params:
                params["target"] = self.target_host
            return {"type": "action", "thought": thought, "tool": tool, "params": params}

        if "FINDING:" in response:
            return {
                "type": "finding",
                "thought": self._extract(response, "THOUGHT:"),
                "title": self._extract(response, "FINDING:"),
                "severity": self._extract(response, "SEVERITY:").strip().lower(),
                "cvss": self._parse_float(self._extract(response, "CVSS:")),
                "description": self._extract(response, "DESCRIPTION:"),
                "remediation": self._extract(response, "REMEDIATION:"),
            }

        if "DONE:" in response:
            return {
                "type": "done",
                "summary": self._extract(response, "DONE:") or self._extract(response, "THOUGHT:"),
            }

        return {"type": "unknown"}

    def _extract(self, text: str, label: str) -> str:
        pattern = rf"{re.escape(label)}\s*(.*?)(?=\n[A-Z]+:|$)"
        match = re.search(pattern, text, re.DOTALL)
        return match.group(1).strip() if match else ""

    def _parse_float(self, value: str) -> float:
        try:
            return float(value.strip())
        except (ValueError, AttributeError):
            return 0.0

    async def _execute_tool(self, tool_name: str, params: dict) -> ToolResult:
        tool = AVAILABLE_TOOLS.get(tool_name)
        if not tool:
            return ToolResult(
                tool_name=tool_name,
                command=f"{tool_name} (unknown tool)",
                output=f"Error: tool '{tool_name}' not available. Available: {list(AVAILABLE_TOOLS.keys())}",
                success=False,
            )
        return await tool.execute(**params)

    async def _save_vulnerability(self, session: AsyncSession, parsed: dict) -> None:
        severity_map = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium, "low": Severity.low, "info": Severity.info}
        vuln = Vulnerability(
            audit_id=self.audit_id,
            title=parsed["title"],
            cvss_score=parsed["cvss"],
            severity=severity_map.get(parsed["severity"], Severity.info),
            description=parsed["description"],
            remediation=parsed.get("remediation"),
        )
        session.add(vuln)
        await session.commit()

    async def _log_step(self, session: AsyncSession, step_type: str, content: str, tool_used: str | None = None, command_executed: str | None = None) -> None:
        step_type_map = {"thought": StepType.thought, "action": StepType.action, "observation": StepType.observation}
        log = AuditLog(
            audit_id=self.audit_id,
            step_type=step_type_map.get(step_type, StepType.thought),
            content=content,
            tool_used=tool_used,
            command_executed=command_executed,
        )
        session.add(log)
        await session.commit()
