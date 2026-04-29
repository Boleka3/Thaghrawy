import subprocess
import os
import asyncio
from typing import Dict, Any, Optional

async def run_gobuster(
    mode: str,
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    threads: int = 10,
    status_codes: str = "200,204,301,302,307,401,403",
    extensions: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run gobuster for directory (dir), DNS (dns), or Virtual Host (vhost) brute-forcing.
    """
    # 1. Validate inputs
    if mode not in ["dir", "dns", "vhost"]:
        return {"error": f"Invalid gobuster mode: {mode}. Supported modes: dir, dns, vhost"}

    if not os.path.isfile(wordlist):
        return {"error": f"Wordlist not found at {wordlist}. Please ensure the wordlist exists on the server."}

    # 2. Build the command
    cmd = ["gobuster", mode]

    # Target flag depends on the mode
    if mode in ["dir", "vhost"]:
        cmd.extend(["-u", target])
    elif mode == "dns":
        cmd.extend(["-d", target])

    # Universal flags (-q for quiet removes the banner)
    cmd.extend(["-w", wordlist, "-t", str(threads), "-q"])

    # Dir-specific flags
    if mode == "dir":
        cmd.extend(["-s", status_codes])
        if extensions:
            cmd.extend(["-x", extensions])

    try:
        # 3. Execute the process
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()

        # If gobuster failed entirely
        if proc.returncode != 0 and not stdout:
            return {"error": f"Gobuster failed: {stderr.decode().strip()}"}

        findings = []
        
        # 4. Dynamically parse the output based on the mode
        for line in stdout.decode().splitlines():
            line = line.strip()
            if not line:
                continue
                
            # Gobuster dns/vhost often prefixes results with "Found: "
            if line.startswith("Found: "):
                line = line[7:].strip()
                
            # If the line contains Status and Size (common in dir and vhost modes)
            if "(Status:" in line and "[Size:" in line:
                path_or_host = line.split("(Status:")[0].strip()
                status = line.split("(Status:")[1].split(")")[0].strip()
                size = line.split("[Size:")[1].split("]")[0].strip()
                
                # Check for redirects
                redirect = ""
                if "[-->" in line:
                    redirect = line.split("[-->")[1].split("]")[0].strip()
                    
                findings.append({
                    "match": path_or_host,
                    "status": int(status) if status.isdigit() else status,
                    "size": int(size) if size.isdigit() else size,
                    "redirect": redirect
                })
            else:
                # Fallback for plain text results (like plain DNS mode)
                findings.append(line)

        return {
            "tool": "gobuster",
            "mode": mode,
            "target": target,
            "wordlist_used": wordlist,
            "total_findings": len(findings),
            "results": findings
        }

    except FileNotFoundError:
        return {"error": "Gobuster not found. Please ensure it is installed (e.g., 'apt install gobuster') and in your PATH."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
