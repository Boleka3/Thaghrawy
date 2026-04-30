import subprocess
import json
import asyncio
from typing import Dict, Any

async def whois(domain: str) -> Dict[str, Any]:

    # Base command
    cmd = ["whois", domain ]

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
        registrar = re.search(r"Registrar:\s*(.*)", output)
        creation_date = re.search(r"Creation Date:\s*(.*)", output)
        expiration_date = re.search(r"Registry Expiry Date:\s*(.*)", output)
        name_servers = re.findall(r"Name Server:\s*(.*)", output)

        return {
            "domain": domain,
            "registrar": registrar.group(1) if registrar else None,
            "creation_date": creation_date.group(1) if creation_date else None,
            "expiration_date": expiration_date.group(1) if expiration_date else None,
            "name_servers": list(set(name_servers)),
            "raw": output[:1000]  # optional: limit raw output
        }

    except FileNotFoundError:
        return {"error": "WHOIS not found. Please install it and ensure it's in PATH."}
    except subprocess.TimeoutExpired:
        return {"error": "WHOIS request timed out."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}