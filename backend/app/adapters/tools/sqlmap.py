from app.adapters.tools.base import BaseTool


class SqlmapTool(BaseTool):
    name = "sqlmap"
    description = "SQL injection scanner - detects and exploits SQL injection vulnerabilities"

    def build_command(self, **kwargs) -> list[str]:
        url = kwargs["url"]
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--level", "2",
            "--risk", "1",
            "--output-dir", "/tmp/sqlmap_output",
        ]
        if kwargs.get("forms"):
            cmd.append("--forms")
        if kwargs.get("crawl"):
            cmd.extend(["--crawl", "2"])
        return cmd
