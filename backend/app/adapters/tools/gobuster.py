from app.adapters.tools.base import BaseTool


class GobusterTool(BaseTool):
    name = "gobuster"
    description = "Directory and file brute forcer"

    def build_command(self, **kwargs) -> list[str]:
        url = kwargs.get("url") or kwargs.get("target") or ""
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/common.txt")
        return ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "20"]
