from app.adapters.tools.base import BaseTool


class FtpAnonTool(BaseTool):
    name = "ftp_anon"
    description = "Tests anonymous FTP login (no credentials) on port 21 and lists the root directory"

    def build_command(self, **kwargs) -> list[str]:
        target = kwargs.get("target") or kwargs.get("host") or ""
        port = kwargs.get("port", 21)
        url = f"ftp://anonymous:anonymous@{target}:{port}/"
        return ["curl", "-s", "-v", "--connect-timeout", "15", "--max-time", "30", url]
