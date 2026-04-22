import subprocess
import json
import asyncio
import os
from typing import Dict, Any, List, Optional

async def run_ffuf(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    headers: Optional[List[str]] = None,
    match_codes: str = "200,204,301,302,307,401,403,405,500",
    filter_codes: Optional[str] = None,
    filter_size: Optional[str] = None,
    threads: int = 40
) -> Dict[str, Any]:
    """
    Fuzz directories, files, and APIs on a web server using ffuf.
    """
    if "FUZZ" not in url:
        if url.endswith("/"):
            url += "FUZZ"
        else:
            url += "/FUZZ"

    if not os.path.isfile(wordlist):
        return {"error": f"Wordlist not found at {wordlist}. Please ensure the wordlist exists on the server."}

    # Base command
    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist,
        "-X", method,
        "-mc", match_codes,
        "-t", str(threads),
        "-json",
        "-s"
    ]

    # Add custom headers if the LLM provided them
    if headers:
        for header in headers:
            cmd.extend(["-H", header])

    if filter_codes:
        cmd.extend(["-fc", filter_codes])
    if filter_size:
        cmd.extend(["-fs", filter_size])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode != 0 and not stdout:
            return {"error": f"ffuf failed: {stderr.decode().strip()}"}

        findings = []
        
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    findings.append({
                        "url": data.get("url"),
                        "status": data.get("status"),
                        "length": data.get("length"),
                        "words": data.get("words"),
                        "lines": data.get("lines"),
                        "redirectlocation": data.get("redirectlocation", "")
                    })
                except json.JSONDecodeError:
                    continue

        return {
            "tool": "ffuf",
            "target": url,
            "method": method,
            "wordlist_used": wordlist,
            "total_findings": len(findings),
            "results": findings
        }

    except FileNotFoundError:
        return {"error": "ffuf not found. Please ensure it is installed and in your PATH."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
