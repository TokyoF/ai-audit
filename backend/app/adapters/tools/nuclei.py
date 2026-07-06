from app.adapters.tools.base import BaseTool


class NucleiTool(BaseTool):
    name = "nuclei"
    description = "Template-based CVE and misconfiguration scanner"

    def build_command(self, **kwargs) -> list[str]:
        url = kwargs.get("url") or kwargs.get("target") or ""
        cmd = ["nuclei", "-target", url, "-silent", "-nc"]
        if kwargs.get("severity"):
            cmd.extend(["-severity", kwargs["severity"]])
        if kwargs.get("tags"):
            cmd.extend(["-tags", kwargs["tags"]])
        return cmd
