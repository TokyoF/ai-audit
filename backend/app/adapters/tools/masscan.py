from app.adapters.tools.base import BaseTool


class MasscanTool(BaseTool):
    name = "masscan"
    description = "Ultra-fast port scanner"

    def build_command(self, **kwargs) -> list[str]:
        target = kwargs.get("target", "")
        ports = kwargs.get("ports", "1-1000")
        rate = str(kwargs.get("rate", "1000"))
        return ["masscan", target, "-p", ports, "--rate", rate]
