import json
import re
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from dataclasses import dataclass

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
"""


@dataclass
class AgentStep:
    step_type: str
    content: str
    tool_used: str | None = None
    command_executed: str | None = None


class ReactAgent:
    def __init__(self, session: AsyncSession, audit: Audit, target_host: str):
        self.session = session
        self.audit = audit
        self.target_host = target_host
        self.history: list[str] = []
        self.max_steps = 20

    async def run(self) -> AsyncGenerator[AgentStep, str | None]:
        self.audit.status = AuditStatus.scanning
        self.session.add(self.audit)
        await self.session.commit()

        initial_prompt = f"Begin a security audit on target: {self.target_host}\nStart with reconnaissance."
        self.history.append(f"USER: {initial_prompt}")

        for step_num in range(self.max_steps):
            prompt = "\n".join(self.history)
            response = await ollama_client.generate(prompt=prompt, system=SYSTEM_PROMPT)
            self.history.append(f"ASSISTANT: {response}")

            parsed = self._parse_response(response)

            if parsed["type"] == "action":
                thought_step = AgentStep(step_type="thought", content=parsed["thought"])
                yield thought_step
                await self._log_step(thought_step)

                tool_result = await self._execute_tool(parsed["tool"], parsed["params"])
                action_step = AgentStep(
                    step_type="action",
                    content=f"Executing {parsed['tool']}",
                    tool_used=parsed["tool"],
                    command_executed=tool_result.command,
                )
                yield action_step
                await self._log_step(action_step)

                observation_step = AgentStep(
                    step_type="observation",
                    content=tool_result.output[:3000],
                )
                yield observation_step
                await self._log_step(observation_step)

                self.history.append(f"OBSERVATION: {tool_result.output[:3000]}")

            elif parsed["type"] == "finding":
                thought_step = AgentStep(step_type="thought", content=parsed["thought"])
                yield thought_step
                await self._log_step(thought_step)

                await self._save_vulnerability(parsed)

                finding_step = AgentStep(
                    step_type="observation",
                    content=f"VULNERABILITY FOUND: [{parsed['severity'].upper()}] {parsed['title']}\n{parsed['description']}",
                )
                yield finding_step
                await self._log_step(finding_step)

                self.audit.status = AuditStatus.awaiting_decision
                self.session.add(self.audit)
                await self.session.commit()

                decision = yield AgentStep(
                    step_type="thought",
                    content="Vulnerability detected. Waiting for auditor decision...",
                )

                if decision == "stop":
                    break
                elif decision == "deeper":
                    self.audit.status = AuditStatus.exploiting
                    self.session.add(self.audit)
                    await self.session.commit()
                    self.history.append(f"USER: Investigate this vulnerability deeper: {parsed['title']}")
                elif decision == "skip":
                    self.audit.status = AuditStatus.scanning
                    self.session.add(self.audit)
                    await self.session.commit()
                    self.history.append("USER: Skip this finding and continue scanning.")
                else:
                    self.audit.status = AuditStatus.scanning
                    self.session.add(self.audit)
                    await self.session.commit()
                    self.history.append("USER: Continue scanning for more vulnerabilities.")

            elif parsed["type"] == "done":
                done_step = AgentStep(step_type="thought", content=parsed["summary"])
                yield done_step
                await self._log_step(done_step)
                break

            else:
                fallback_step = AgentStep(step_type="thought", content=response[:500])
                yield fallback_step
                await self._log_step(fallback_step)
                self.history.append("USER: Please follow the required response format. Continue the audit.")

        self.audit.status = AuditStatus.idle
        self.audit.finished_at = datetime.now(timezone.utc)
        self.session.add(self.audit)
        await self.session.commit()

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

    async def _save_vulnerability(self, parsed: dict) -> None:
        severity_map = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium, "low": Severity.low, "info": Severity.info}
        vuln = Vulnerability(
            audit_id=self.audit.id,
            title=parsed["title"],
            cvss_score=parsed["cvss"],
            severity=severity_map.get(parsed["severity"], Severity.info),
            description=parsed["description"],
            remediation=parsed.get("remediation"),
        )
        self.session.add(vuln)
        await self.session.commit()

    async def _log_step(self, step: AgentStep) -> None:
        step_type_map = {"thought": StepType.thought, "action": StepType.action, "observation": StepType.observation}
        log = AuditLog(
            audit_id=self.audit.id,
            step_type=step_type_map.get(step.step_type, StepType.thought),
            content=step.content,
            tool_used=step.tool_used,
            command_executed=step.command_executed,
        )
        self.session.add(log)
        await self.session.commit()
