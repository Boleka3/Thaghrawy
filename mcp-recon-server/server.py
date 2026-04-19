import json
import asyncio
from typing import Any
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Import your tool implementations
from tools.amass import subdomain_enum_amass
from tools.subfinder import subdomain_enum_subfinder

server = Server("recon-server")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        # --- AMASS TOOL ---
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
        
        # --- SUBFINDER TOOL ---
        types.Tool(
            name="subdomain_enum_subfinder",
            description="Enumerate subdomains using Subfinder. Highly configurable for specific sources and rate limits.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g., example.com)",
                    },
                    "all_sources": {
                        "type": "boolean",
                        "description": "Use all sources (slower but more comprehensive)",
                        "default": False,
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Use only sources that can handle subdomains recursively",
                        "default": False,
                    },
                    "sources": {
                        "type": "string",
                        "description": "Comma-separated list of specific sources to use (e.g., 'alienvault,crtsh')",
                    },
                    "exclude_sources": {
                        "type": "string",
                        "description": "Comma-separated list of sources to exclude (e.g., 'github,waybackarchive')",
                    },
                    "rate_limit": {
                        "type": "integer",
                        "description": "Maximum number of HTTP requests to send per second",
                    },
                    "max_time": {
                        "type": "integer",
                        "description": "Maximum minutes to wait for enumeration results",
                    }
                },
                "required": ["domain"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict[str, Any]
) -> list[types.TextContent]:
    try:
        # Route to Amass
        if name == "subdomain_enum_amass":
            result = await subdomain_enum_amass(
                domain=arguments["domain"],
                mode=arguments.get("mode", "passive"),
                brute=arguments.get("brute", False),
            )
            
        # Route to Subfinder
        elif name == "subdomain_enum_subfinder":
            result = await subdomain_enum_subfinder(
                domain=arguments["domain"],
                all_sources=arguments.get("all_sources", False),
                recursive=arguments.get("recursive", False),
                sources=arguments.get("sources"),
                exclude_sources=arguments.get("exclude_sources"),
                rate_limit=arguments.get("rate_limit"),
                max_time=arguments.get("max_time")
            )
            
        else:
            raise ValueError(f"Unknown tool: {name}")

        # Return the JSON result from the chosen tool
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
