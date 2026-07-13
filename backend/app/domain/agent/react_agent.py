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
from app.domain.agent.finding_extractor import extract_findings, normalize_finding_title
from app.domain.models.audit import Audit, AuditStatus
from app.domain.models.audit_log import AuditLog, StepType
from app.domain.models.vulnerability import Severity, Vulnerability


SYSTEM_PROMPT = """You are an expert cybersecurity penetration tester AI agent. You perform security audits by analyzing targets using available tools.

Available tools:
- nmap: Port scanner. Parameters: target (required), scan_type (basic|full|udp|vuln, default: basic)
- hydra: Brute force tool. Parameters: target (required), service (ssh|ftp|http, default: ssh), username (default: admin)
- sqlmap: SQL injection scanner. Parameters: url OR target (a bare host is accepted and auto-crawled), forms (bool), crawl (bool). Prefer a parametrized URL like http://<target>/product?id=1
- nikto: web server vulnerability scanner. Parameters: target/url (required), optional port
- whatweb: web technology fingerprinting. Parameters: url (required)
- gobuster: directory/file brute force. Parameters: url (required), optional wordlist
- masscan: ultra-fast port scanner. Parameters: target (required), optional ports (e.g. "1-65535"), optional rate
- sslscan: TLS/SSL cipher & certificate audit. Parameters: target (required), optional port
- dnsrecon: DNS enumeration. Parameters: domain (required)
- enum4linux: SMB/Samba enumeration. Parameters: target (required)
- nuclei: template-based CVE/misconfig scanner (use for known-CVE detection). Parameters: url/target (required), optional severity (critical,high,medium), optional tags
- ftp_anon: Tests anonymous FTP login (no credentials) on port 21 and lists the root directory. Parameters: target (required), port (optional, default 21)

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
CVE: <CVE-id if known, else omit>
POC: <short evidence/proof, e.g. the command output line that proves it>

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
- After enumeration, pivot to service-specific tools: use ftp_anon to check anonymous FTP access when port 21 is open, hydra for credential brute force on exposed auth services (ssh/ftp/http), sqlmap for web apps with parameters.
- Only respond DONE when you have tried multiple distinct techniques and no further useful action remains. Do not declare DONE just because one scan finished.
- Before concluding (DONE), ensure you have enumerated web content with gobuster, scanned the web server with nikto and nuclei, and tested any web parameters with sqlmap when an HTTP service is open. Do not conclude after only nmap — a thorough audit runs multiple service-specific tools.
- If the operator asks to test SQL injection (menciona "SQL", "inyección" o "injection"), you MUST use the sqlmap tool (never curl) with a parametrized URL. Example: ACTION: sqlmap / PARAMS: {"url": "http://<target-host>/product?id=1"}. Always use the target host, never localhost.

REPORTING:
- Whenever a tool reveals a concrete weakness, you MUST emit a FINDING block (with SEVERITY and CVSS) BEFORE moving on to the next action. Examples: valid credentials found by hydra (critical), SQL injection confirmed by sqlmap (critical), outdated/vulnerable service versions from nmap (medium/high), issues reported by nikto/nuclei.
- Do NOT respond DONE until every discovered weakness has a corresponding FINDING.
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
    resume_context: str | None = None
    step_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    decision_event: asyncio.Event = field(default_factory=asyncio.Event)
    decision_value: str = "continue"
    is_running: bool = False
    _history: list[str] = field(default_factory=list)
    _failed_tools: set = field(default_factory=set)
    _executed_actions: set = field(default_factory=set)
    _saved_finding_titles: set = field(default_factory=set)
    _cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    _consecutive_noops: int = 0
    _consecutive_dups: int = 0
    _actions_taken: int = 0
    _resume_guard_used: bool = False
    max_steps: int = 20

    async def run(self, session: AsyncSession) -> None:
        self.is_running = True

        audit = await session.get(Audit, self.audit_id)
        audit.status = AuditStatus.scanning
        session.add(audit)
        await session.commit()

        self._history.clear()
        self._executed_actions.clear()
        self._saved_finding_titles.clear()
        self._consecutive_noops = 0
        self._consecutive_dups = 0
        self._actions_taken = 0
        self._resume_guard_used = False

        await self._load_history(session)

        try:
            existing_vulns = await session.exec(
                select(Vulnerability).where(Vulnerability.audit_id == self.audit_id)
            )
            for vuln in existing_vulns.all():
                self._saved_finding_titles.add(normalize_finding_title(vuln.title))
        except Exception:
            pass

        if self._history:
            self._history.append("USER: Resume this audit. Review what was already tried above and continue with a NEW technique or tool that has NOT been used yet. Do NOT respond DONE unless you have genuinely exhausted distinct approaches.")
        else:
            initial_prompt = f"Begin a security audit on target: {self.target_host}\nStart with reconnaissance."
            self._history.append(f"USER: {initial_prompt}")

        if self.resume_context:
            self._history.append(
                f"USER: El operador te da este contexto adicional y te ordena continuar: {self.resume_context}. "
                f"Actúa AHORA sobre esta indicación con una ACTION concreta usando una herramienta. NO emitas DONE hasta ejecutarla."
            )
            await self._log_step(session, "thought", f"📝 Auditor: {self.resume_context}")

        try:
            for _ in range(self.max_steps):
                if self._cancel_event.is_set():
                    break
                prompt = self._build_prompt()

                await self._emit(AgentStep(step_type="thought", content="Thinking..."))

                try:
                    response = await ollama_client.generate(prompt=prompt, system=SYSTEM_PROMPT)
                except Exception as e:
                    await self._emit(AgentStep(step_type="error", content=f"El modelo de IA no respondió (timeout o error): {e}"))
                    break
                self._history.append(f"ASSISTANT: {response}")

                parsed = self._parse_response(response)

                if parsed["type"] == "action":
                    await self._emit(AgentStep(step_type="thought", content=parsed["thought"]))
                    await self._log_step(session, "thought", parsed["thought"])

                    action_key = f"{parsed['tool']}:{json.dumps(parsed['params'], sort_keys=True)}"
                    if action_key in self._executed_actions:
                        self._consecutive_dups += 1
                        if self._consecutive_dups >= 3:
                            await self._emit(AgentStep(step_type="thought", content="Sin nuevas técnicas que probar; concluyendo la auditoría."))
                            break
                        duplicate_msg = (
                            f"You already executed '{parsed['tool']}' with these exact parameters. "
                            "Do NOT repeat it. Choose a different tool or a different nmap scan_type."
                        )
                        await self._emit(AgentStep(step_type="observation", content=duplicate_msg))
                        await self._log_step(session, "observation", duplicate_msg)
                        self._history.append(f"OBSERVATION: {duplicate_msg}")
                        continue
                    self._executed_actions.add(action_key)
                    self._consecutive_noops = 0
                    self._consecutive_dups = 0
                    self._actions_taken += 1

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

                    if not is_env_error:
                        await self._auto_extract_findings(session, tool_result.tool_name, tool_result.command, tool_result.output)

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
                    await self._emit(AgentStep(step_type="finding", content=finding_msg))
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
                    if self.resume_context and self._actions_taken == 0 and not self._resume_guard_used:
                        self._resume_guard_used = True
                        nudge = (
                            f"USER: NO concluyas todavía. El operador te pidió una acción concreta y aún no has "
                            f"ejecutado ninguna herramienta. Emite AHORA un bloque ACTION real. "
                            f"Para probar inyección SQL usa la herramienta sqlmap (NO curl) con "
                            f'PARAMS: {{"url": "http://{self.target_host}/product?id=1"}}. '
                            f"Usa el host del objetivo, no localhost. No respondas DONE."
                        )
                        self._history.append(nudge)
                        await self._emit(AgentStep(step_type="thought", content="El operador pidió una acción concreta; reintentando en lugar de concluir."))
                        continue
                    await self._emit(AgentStep(step_type="thought", content=parsed["summary"]))
                    await self._log_step(session, "thought", parsed["summary"])
                    break

                elif parsed["type"] == "noop":
                    self._consecutive_noops += 1
                    if self._consecutive_noops >= 2:
                        summary = parsed["thought"] or "Audit completed"
                        await self._emit(AgentStep(step_type="thought", content=summary))
                        await self._log_step(session, "thought", summary)
                        break
                    self._history.append(
                        "USER: No hay un humano esperando. NO esperes instrucciones. Continúa de forma autónoma: "
                        "elige la siguiente herramienta útil contra el objetivo (por ejemplo sqlmap sobre servicios web, "
                        "nikto, gobuster, hydra) y emite una ACTION concreta, o si de verdad agotaste todo emite DONE:."
                    )
                    continue

                else:
                    await self._emit(AgentStep(step_type="thought", content=response[:500]))
                    await self._log_step(session, "thought", response[:500])
                    self._history.append("USER: Please follow the required response format. Continue the audit.")

        finally:
            try:
                audit = await session.get(Audit, self.audit_id)
                if audit:
                    audit.status = AuditStatus.idle
                    audit.finished_at = datetime.now(timezone.utc)
                    session.add(audit)
                    await session.commit()
            except Exception:
                pass
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

    def _build_prompt(self) -> str:
        # Keep the most recent context to fit the model's window.
        MAX_ENTRIES = 24
        PER_ENTRY_CHARS = 1500
        TOTAL_CHARS = 12000
        entries = self._history[-MAX_ENTRIES:]
        trimmed = []
        for e in entries:
            if len(e) > PER_ENTRY_CHARS:
                e = e[:PER_ENTRY_CHARS] + " …[truncado]"
            trimmed.append(e)
        prompt = "\n".join(trimmed)
        # Hard cap: keep the TAIL (most recent + operator instruction is last)
        if len(prompt) > TOTAL_CHARS:
            prompt = prompt[-TOTAL_CHARS:]
        return prompt

    async def _emit(self, step: AgentStep) -> None:
        await self.step_queue.put(step)

    def _parse_response(self, response: str) -> dict:
        response = response.strip()

        if "DONE:" in response:
            return {
                "type": "done",
                "summary": self._extract(response, "DONE:") or self._extract(response, "THOUGHT:") or "Audit completed",
            }

        if "ACTION:" in response:
            thought = self._extract(response, "THOUGHT:")
            tool = self._extract(response, "ACTION:").strip().lower()
            if tool.startswith(("done", "finish", "complete", "stop")):
                return {
                    "type": "done",
                    "summary": thought or "Audit completed",
                }
            if tool.startswith(("none", "noop", "no-op", "no_op", "wait", "n/a", "na", "pass", "null", "nothing")):
                return {"type": "noop", "thought": thought}
            params_str = self._extract(response, "PARAMS:")
            try:
                params = json.loads(params_str)
            except (json.JSONDecodeError, TypeError):
                params = {"target": self.target_host}
            if "target" not in params and "url" not in params:
                params["target"] = self.target_host
            return {"type": "action", "thought": thought, "tool": tool, "params": params}

        if "FINDING:" in response:
            cve = self._extract(response, "CVE:")
            poc = self._extract(response, "POC:")
            return {
                "type": "finding",
                "thought": self._extract(response, "THOUGHT:"),
                "title": self._extract(response, "FINDING:"),
                "severity": self._extract(response, "SEVERITY:").strip().lower(),
                "cvss": self._parse_float(self._extract(response, "CVSS:")),
                "description": self._extract(response, "DESCRIPTION:"),
                "remediation": self._extract(response, "REMEDIATION:"),
                "cve_id": cve or None,
                "poc": poc or None,
            }

        if response.strip().lower().startswith("done"):
            return {"type": "done", "summary": self._extract(response, "THOUGHT:") or "Audit completed"}

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
        if tool_name.startswith(("done", "finish", "complete", "stop")):
            return ToolResult(tool_name=tool_name, command=tool_name, output="(audit marked done)", success=True)
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
        title = parsed["title"]
        norm = normalize_finding_title(title)
        if norm in self._saved_finding_titles:
            return  # already recorded (possibly by auto-extract or a prior run)
        severity_map = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium, "low": Severity.low, "info": Severity.info}
        cid = parsed.get("cve_id")
        cid = cid if (cid and len(cid) <= 20) else None
        vuln = Vulnerability(
            audit_id=self.audit_id,
            title=title,
            cvss_score=parsed["cvss"],
            severity=severity_map.get(parsed["severity"], Severity.info),
            description=parsed["description"],
            remediation=parsed.get("remediation"),
            cve_id=cid,
            poc=parsed.get("poc"),
        )
        session.add(vuln)
        self._saved_finding_titles.add(norm)
        await session.commit()

    async def _auto_extract_findings(self, session: AsyncSession, tool_name: str, command: str, output: str) -> None:
        try:
            findings = extract_findings(tool_name, command, output)
        except Exception:
            return

        severity_map = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium, "low": Severity.low, "info": Severity.info}
        added = False
        try:
            for finding in findings:
                title = finding.get("title")
                norm = normalize_finding_title(title)
                if not title or norm in self._saved_finding_titles:
                    continue

                severity = str(finding.get("severity", "info")).lower()
                vuln = Vulnerability(
                    audit_id=self.audit_id,
                    title=title,
                    cvss_score=finding.get("cvss", 0.0),
                    severity=severity_map.get(severity, Severity.info),
                    description=finding.get("description") or title,
                    remediation=finding.get("remediation"),
                    cve_id=finding.get("cve_id"),
                    poc=finding.get("poc"),
                )
                session.add(vuln)
                self._saved_finding_titles.add(norm)
                added = True

                await self._emit(AgentStep(
                    step_type="finding",
                    content=f"[{severity.upper()}] {title}",
                ))

            if added:
                await session.commit()
        except Exception:
            pass

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
