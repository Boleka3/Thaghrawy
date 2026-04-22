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
from tools.httpx import run_httpx
from tools.ffuf import run_ffuf

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
# ---- HTTPX TOOL  ----
        types.Tool(
            name="probe_live_hosts_httpx",
            description="Probes a list of domains to find live HTTP/HTTPS web servers. Extracts status codes, titles, and web technologies.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domains to probe (e.g., ['example.com', 'dev.example.com'])",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Comma-separated ports to probe (e.g., '80,443,8080,8443')",
                    },
                    "tech_detect": {
                        "type": "boolean",
                        "description": "Enable Wappalyzer technology detection to find what the site is built with",
                        "default": False,
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Follow HTTP redirects",
                        "default": False,
                    },
                    "match_codes": {
                        "type": "string",
                        "description": "Only show results with these status codes (e.g., '200,301,403')",
                    },
                    "filter_codes": {
                        "type": "string",
                        "description": "Hide results with these status codes (e.g., '404,500')",
                    }
                },
                "required": ["domains"],
            },
        ),

        # --- FFUF TOOL ---
        types.Tool(
            name="fuzz_web_directories_ffuf",
            description="Fuzz directories, files, and APIs on a web server using ffuf. The URL must contain the keyword 'FUZZ'.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL containing the word FUZZ (e.g., 'https://target.com/FUZZ')",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Absolute path to the wordlist file on the server",
                        "default": "/usr/share/wordlists/dirb/common.txt",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method to use (GET, POST, PUT, etc.)",
                        "default": "GET",
                    },
                    "headers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Custom headers to include (e.g., ['Authorization: Bearer token123', 'Cookie: session=abc'])",
                    },
                    "match_codes": {
                        "type": "string",
                        "description": "Comma-separated HTTP status codes to match",
                        "default": "200,204,301,302,307,401,403,405,500",
                    },
                    "filter_codes": {
                        "type": "string",
                        "description": "Comma-separated HTTP status codes to ignore (e.g., '404')",
                    },
                    "filter_size": {
                        "type": "string",
                        "description": "Filter responses by specific size (useful for ignoring standard 404 pages that return a 200 code)",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 40,
                    }
                },
                "required": ["url"],
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
            # Route to httpx
        elif name == "probe_live_hosts_httpx":
            result = await run_httpx(
                domains=arguments["domains"],
                ports=arguments.get("ports"),
                tech_detect=arguments.get("tech_detect", False),
                follow_redirects=arguments.get("follow_redirects", False),
                match_codes=arguments.get("match_codes"),
                filter_codes=arguments.get("filter_codes")
            )
            # Route to ffuf
        elif name == "fuzz_web_directories_ffuf":
            result = await run_ffuf(
                url=arguments["url"],
                wordlist=arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                method=arguments.get("method", "GET"),
                headers=arguments.get("headers"),
                match_codes=arguments.get("match_codes", "200,204,301,302,307,401,403,405,500"),
                filter_codes=arguments.get("filter_codes"),
                filter_size=arguments.get("filter_size"),
                threads=arguments.get("threads", 40)
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
