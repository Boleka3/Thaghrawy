import subprocess
import json
import asyncio
from typing import Dict, Any

async def subdomain_enum_amass(domain: str, mode: str = "passive", brute: bool = False) -> Dict[str, Any]:
    """
    Enumerate subdomains using OWASP Amass.

    Args:
        domain: Target domain (e.g., "example.com").
        mode: Scan mode - "passive" (no direct queries) or "active".
        brute: Enable DNS brute-forcing for deeper discovery.

    Returns:
        A dictionary with the list of subdomains or an error message.
    """
    # Base command
    cmd = ["amass", "enum", "-d", domain, "-json", "/dev/stdout"]

    # Add mode-specific flags
    if mode == "passive":
        cmd.append("-passive")
    elif mode == "active":
        cmd.append("-active")

    if brute:
        cmd.append("-brute")

    try:
        # Run the command
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            return {"error": f"Amass failed: {stderr.decode().strip()}"}

        # Parse JSON Lines output
        subdomains: set[str] = set()
        for line in stdout.decode().splitlines():
            if line.strip():
                data = json.loads(line)
                if 'name' in data:
                    subdomains.add(data['name'])

        return {
            "domain": domain,
            "mode": mode,
            "brute": brute,
            "subdomains": sorted(list(subdomains)),
            "count": len(subdomains)
        }

    except FileNotFoundError:
        return {"error": "Amass not found. Please ensure it is installed and in your PATH."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

