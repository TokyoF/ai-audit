from app.adapters.tools.base import BaseTool


class Enum4linuxTool(BaseTool):
    name = "enum4linux"
    description = "SMB/Samba enumeration tool"

    def build_command(self, **kwargs) -> list[str]:
        target = kwargs.get("target") or kwargs.get("host") or ""
        return ["enum4linux", "-a", target]
