from app.adapters.tools.base import BaseTool


class NmapTool(BaseTool):
    name = "nmap"
    description = "Port scanner - discovers open ports, services, and versions on a target"

    def build_command(self, **kwargs) -> list[str]:
        target = kwargs["target"]
        scan_type = kwargs.get("scan_type", "basic")
        cmd = ["nmap"]
        if scan_type == "basic":
            cmd.extend(["-sV", "-sC", "--top-ports", "1000", "-T4"])
        elif scan_type == "full":
            cmd.extend(["-sV", "-sC", "-p-", "-T4"])
        elif scan_type == "udp":
            cmd.extend(["-sU", "--top-ports", "100", "-T4"])
        elif scan_type == "vuln":
            cmd.extend(["-sV", "--script", "vuln", "-T4"])
        cmd.append(target)
        return cmd
