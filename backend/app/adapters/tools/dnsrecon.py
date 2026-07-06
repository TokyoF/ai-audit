from app.adapters.tools.base import BaseTool


class DnsreconTool(BaseTool):
    name = "dnsrecon"
    description = "DNS enumeration tool"

    def build_command(self, **kwargs) -> list[str]:
        domain = kwargs.get("domain") or kwargs.get("target") or ""
        return ["dnsrecon", "-d", domain]
