import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass


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
        cmd = self.build_command(**kwargs)
        command_str = " ".join(cmd)
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            output = stdout.decode(errors="replace")
            if stderr:
                output += "\n" + stderr.decode(errors="replace")
            return ToolResult(
                tool_name=self.name,
                command=command_str,
                output=output.strip(),
                success=process.returncode == 0,
            )
        except asyncio.TimeoutError:
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
                output=f"Error: {self.name} not found. Make sure it is installed.",
                success=False,
            )
