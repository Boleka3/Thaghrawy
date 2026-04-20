import subprocess
import json
import asyncio
from typing import Dict, Any, List, Optional

async def run_httpx(
    domains: List[str],
    ports: Optional[str] = None,
    tech_detect: bool = False,
    follow_redirects: bool = False,
    match_codes: Optional[str] = None,
    filter_codes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Probe a list of domains to find live web servers and extract information.
    """
    # Hardcoded flags: -silent for clean output, -json for structured parsing
    # We automatically include status-code, title, and IP as they are universally useful.
    cmd = ["httpx", "-silent", "-json", "-sc", "-title", "-ip"]

    # Optional flags controlled by the LLM
    if ports:
        cmd.extend(["-p", ports])
    if tech_detect:
        cmd.append("-td")
    if follow_redirects:
        cmd.append("-fl")
    if match_codes:
        cmd.extend(["-mc", match_codes])
    if filter_codes:
        cmd.extend(["-fc", filter_codes])

    try:
        # We use stdin=subprocess.PIPE so we can feed the list of domains directly to httpx
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Convert the Python list of domains into a single string separated by newlines
        input_data = "\n".join(domains).encode()
        
        # Send the domains to httpx and wait for the response
        stdout, stderr = await proc.communicate(input=input_data)

        if proc.returncode != 0 and not stdout:
            return {"error": f"httpx failed: {stderr.decode().strip()}"}

        live_hosts = []
        
        # Parse the JSON Lines output
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    # Clean up the output to only send what the LLM needs to see
                    clean_data = {
                        "url": data.get("url"),
                        "status_code": data.get("status_code"),
                        "title": data.get("title", ""),
                        "ip": data.get("host", ""),
                    }
                    if tech_detect and "tech" in data:
                        clean_data["tech"] = data["tech"]
                        
                    live_hosts.append(clean_data)
                except json.JSONDecodeError:
                    continue

        return {
            "tool": "httpx",
            "hosts_scanned": len(domains),
            "live_hosts_found": len(live_hosts),
            "results": live_hosts
        }

    except FileNotFoundError:
        return {"error": "httpx not found. Please ensure it is installed and in your PATH."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
