import subprocess
import json
import asyncio
from typing import Dict, Any

async def subdomain_enum_subfinder(domain: str) -> Dict[str, Any]:
    """
    Enumerate subdomains using ProjectDiscovery's Subfinder.
    """
    # -silent removes banner/logs, -json outputs JSON lines
    cmd = ["subfinder", "-d", domain, "-json", "-silent"]

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
        
        # Parse JSON Lines output
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    # Subfinder JSON output uses the 'host' key for the subdomain
                    if 'host' in data:
                        subdomains.add(data['host'])
                except json.JSONDecodeError:
                    continue

        return {
            "domain": domain,
            "tool": "subfinder",
            "subdomains": sorted(list(subdomains)),
            "count": len(subdomains)
        }

    except FileNotFoundError:
        return {"error": "Subfinder not found. Please ensure it is installed and in your PATH."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
