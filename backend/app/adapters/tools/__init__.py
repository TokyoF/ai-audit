from app.adapters.tools.base import BaseTool, ToolResult
from app.adapters.tools.dnsrecon import DnsreconTool
from app.adapters.tools.enum4linux import Enum4linuxTool
from app.adapters.tools.gobuster import GobusterTool
from app.adapters.tools.hydra import HydraTool
from app.adapters.tools.masscan import MasscanTool
from app.adapters.tools.nikto import NiktoTool
from app.adapters.tools.nmap import NmapTool
from app.adapters.tools.nuclei import NucleiTool
from app.adapters.tools.sqlmap import SqlmapTool
from app.adapters.tools.sslscan import SslscanTool
from app.adapters.tools.whatweb import WhatWebTool

AVAILABLE_TOOLS: dict[str, BaseTool] = {
    "nmap": NmapTool(),
    "hydra": HydraTool(),
    "sqlmap": SqlmapTool(),
    "nikto": NiktoTool(),
    "whatweb": WhatWebTool(),
    "gobuster": GobusterTool(),
    "masscan": MasscanTool(),
    "sslscan": SslscanTool(),
    "dnsrecon": DnsreconTool(),
    "enum4linux": Enum4linuxTool(),
    "nuclei": NucleiTool(),
}

__all__ = [
    "BaseTool",
    "ToolResult",
    "AVAILABLE_TOOLS",
    "NmapTool",
    "HydraTool",
    "SqlmapTool",
    "NiktoTool",
    "WhatWebTool",
    "GobusterTool",
    "MasscanTool",
    "SslscanTool",
    "DnsreconTool",
    "Enum4linuxTool",
    "NucleiTool",
]
