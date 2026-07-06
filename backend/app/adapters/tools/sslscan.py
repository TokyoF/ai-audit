from app.adapters.tools.base import BaseTool


class SslscanTool(BaseTool):
    name = "sslscan"
    description = "TLS/SSL cipher and certificate audit tool"

    def build_command(self, **kwargs) -> list[str]:
        target = kwargs.get("target") or kwargs.get("host") or ""
        if "port" in kwargs:
            target = f"{target}:{kwargs['port']}"
        return ["sslscan", target]
