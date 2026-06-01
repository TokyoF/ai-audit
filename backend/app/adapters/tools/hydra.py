from app.adapters.tools.base import BaseTool


class HydraTool(BaseTool):
    name = "hydra"
    description = "Brute force tool - tests credentials on SSH, FTP, and other services"

    def build_command(self, **kwargs) -> list[str]:
        target = kwargs["target"]
        service = kwargs.get("service", "ssh")
        username = kwargs.get("username", "admin")
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        cmd = [
            "hydra",
            "-l", username,
            "-P", wordlist,
            "-t", "4",
            "-f",
            target,
            service,
        ]
        return cmd
