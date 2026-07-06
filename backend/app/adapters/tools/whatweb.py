from app.adapters.tools.base import BaseTool


class WhatWebTool(BaseTool):
    name = "whatweb"
    description = "Web technology fingerprinting tool"

    def build_command(self, **kwargs) -> list[str]:
        target = kwargs.get("url") or kwargs.get("target") or ""
        return ["whatweb", "-a", "3", target]
