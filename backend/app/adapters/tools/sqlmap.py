from app.adapters.tools.base import BaseTool


class SqlmapTool(BaseTool):
    name = "sqlmap"
    description = "SQL injection scanner - detects and exploits SQL injection vulnerabilities"

    def build_command(self, **kwargs) -> list[str]:
        url = kwargs.get("url") or kwargs.get("target") or ""
        url = str(url).strip()
        # Accept a bare host (no scheme) and make it a testable URL.
        if url and not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--level", "2",
            "--risk", "1",
            "--output-dir", "/tmp/sqlmap_output",
        ]
        # If there is no query parameter to inject, let sqlmap discover inputs.
        no_param = "?" not in url
        want_forms = bool(kwargs.get("forms")) or no_param
        want_crawl = bool(kwargs.get("crawl")) or no_param
        if want_forms:
            cmd.append("--forms")
        if want_crawl:
            cmd.extend(["--crawl", "2"])
        return cmd
