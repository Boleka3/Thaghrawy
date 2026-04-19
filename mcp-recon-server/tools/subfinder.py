import subprocess
import json
import asyncio
from typing import Dict, Any, Optional

async def subdomain_enum_subfinder(
    domain: str, 
    all_sources: bool = False,
    recursive: bool = False,
    sources: Optional[str] = None,
    exclude_sources: Optional[str] = None,
    rate_limit: Optional[int] = None,
    max_time: Optional[int] = None
) -> Dict[str, Any]:
    
    # Base command: always run silent and output JSON
    cmd = ["subfinder", "-d", domain, "-json", "-silent"]

    # Append boolean flags
    if all_sources:
        cmd.append("-all")
    if recursive:
        cmd.append("-recursive")
        
    # Append string/integer flags if they are provided
    if sources:
        cmd.extend(["-sources", sources])
    if exclude_sources:
        cmd.extend(["-exclude-sources", exclude_sources])
    if rate_limit:
        cmd.extend(["-rl", str(rate_limit)])
    if max_time:
        cmd.extend(["-max-time", str(max_time)])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            return {"error": f"Subfinder failed: {stderr.decode().strip()}"}

        subdomains: set[str] = set()
        
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    if 'host' in data:
                        subdomains.add(data['host'])
                except json.JSONDecodeError:
                    continue

        return {
            "domain": domain,
            "tool": "subfinder",
            "parameters_used": {
                "all_sources": all_sources,
                "recursive": recursive,
                "sources": sources,
                "exclude_sources": exclude_sources,
                "rate_limit": rate_limit,
                "max_time": max_time
            },
            "subdomains": sorted(list(subdomains)),
            "count": len(subdomains)
        }

    except FileNotFoundError:
        return {"error": "Subfinder not found. Please ensure it is installed and in your PATH."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
