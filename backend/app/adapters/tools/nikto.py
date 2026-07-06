from app.adapters.tools.base import BaseTool


class NiktoTool(BaseTool):
    name = "nikto"
    description = "Web server vulnerability scanner"

    def build_command(self, **kwargs) -> list[str]:
        target = kwargs.get("target") or kwargs.get("url") or ""
        cmd = ["nikto", "-h", target]
        if "port" in kwargs:
            cmd.extend(["-p", str(kwargs["port"])])
        return cmd
