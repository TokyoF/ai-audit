from app.adapters.tools.base import BaseTool, ToolResult
from app.adapters.tools.hydra import HydraTool
from app.adapters.tools.nmap import NmapTool
from app.adapters.tools.sqlmap import SqlmapTool

AVAILABLE_TOOLS: dict[str, BaseTool] = {
    "nmap": NmapTool(),
    "hydra": HydraTool(),
    "sqlmap": SqlmapTool(),
}

__all__ = ["BaseTool", "ToolResult", "AVAILABLE_TOOLS", "NmapTool", "HydraTool", "SqlmapTool"]
