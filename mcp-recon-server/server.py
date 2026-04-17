import json
import asyncio
from typing import Any
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Import your tool implementations
from tools.amass import subdomain_enum_amass

server = Server("recon-server")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="subdomain_enum_amass",
            description="Enumerate subdomains using OWASP Amass. Supports passive/active modes and brute-force.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g., example.com)",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["passive", "active"],
                        "description": "passive = no direct queries, active = direct DNS queries",
                        "default": "passive",
                    },
                    "brute": {
                        "type": "boolean",
                        "description": "Enable DNS brute-forcing (slower but more thorough)",
                        "default": False,
                    },
                },
                "required": ["domain"],
            },
        ),
        
        # ... other tools (dns_lookup, port_scan, etc.)
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict[str, Any]
) -> list[types.TextContent]:
    try:
        if name == "subdomain_enum_amass":
            result = await subdomain_enum_amass(
                domain=arguments["domain"],
                mode=arguments.get("mode", "passive"),
                brute=arguments.get("brute", False),
            )
        # Add other tools here (elif name == "dns_lookup": ...)
        else:
            raise ValueError(f"Unknown tool: {name}")

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error: {str(e)}")]


async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="recon-server",
                server_version="0.1.0",
                capabilities=types.ServerCapabilities(),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
