"""Minimal stdio MCP server used by automated tests for PluginSessionManager."""

from __future__ import annotations

import base64

from mcp.server.mcpserver import MCPServer
from mcp.types import ImageContent, TextContent

# 1x1 valid transparent PNG
_PIXEL_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)

srv = MCPServer("mock-stdio-plugin")


@srv.tool()
def echo_info(message: str = "ok") -> str:
    """Echo a simple text payload."""
    return f"mock:{message}"


@srv.tool()
def render_preview() -> list[TextContent | ImageContent]:
    """Return a tiny 1x1 PNG ImageContent for preview pipeline tests."""
    return [
        TextContent(type="text", text="rendered preview"),
        ImageContent(type="image", data=_PIXEL_PNG_B64, mimeType="image/png"),
    ]


if __name__ == "__main__":
    srv.run(transport="stdio")
