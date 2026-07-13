import asyncio
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass


TOOLS_CONTAINER = "aiaudit-tools"
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


@dataclass
class ToolResult:
    tool_name: str
    command: str
    output: str
    success: bool


class BaseTool(ABC):
    name: str
    description: str

    @abstractmethod
    def build_command(self, **kwargs) -> list[str]:
        ...

    async def execute(self, **kwargs) -> ToolResult:
        def _norm(value):
            if isinstance(value, str):
                value = value.strip()
                if value in ("localhost", "127.0.0.1"):
                    return "host.docker.internal"
            return value

        normalized_kwargs = {key: _norm(value) for key, value in kwargs.items()}
        cmd = self.build_command(**normalized_kwargs)
        command_str = " ".join(cmd)
        docker_cmd = ["docker", "exec", TOOLS_CONTAINER] + cmd
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            output = stdout.decode(errors="replace")
            if stderr:
                err_text = stderr.decode(errors="replace")
                if err_text.strip():
                    output += "\n" + err_text
            output = _ANSI_RE.sub("", output)
            output = output.strip() or "(no output)"
            if process.returncode != 0:
                lowered = output.lower()
                if (
                    "no such container" in lowered
                    or "is not running" in lowered
                    or "cannot connect to the docker daemon" in lowered
                    or "error during connect" in lowered
                ):
                    output = "ENV_ERROR: " + output
            return ToolResult(
                tool_name=self.name,
                command=command_str,
                output=output,
                success=process.returncode == 0,
            )
        except asyncio.TimeoutError:
            if process is not None:
                process.kill()
                await process.wait()
            return ToolResult(
                tool_name=self.name,
                command=command_str,
                output="Error: command timed out after 300 seconds",
                success=False,
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name=self.name,
                command=command_str,
                output="ENV_ERROR: docker not found. Make sure Docker is running.",
                success=False,
            )
