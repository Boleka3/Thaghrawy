import subprocess
import json
import asyncio
from typing import Dict, Any

async def subfinder(domain:str, mode:str = "passive", brute:bool = False, hosts_is_up:bool = False, scan_type:str = "-sS"):
    cmd = ["nmap", domain]
    
    if mode == "passive":
        cmd.append("-passive")
    else:
        cmd.append("-active")
    
    if scan_type == "ACK":
        cmd.append("-sA")
    elif scan_type == "SYN":
        cmd.append("-sS")
    elif scan_type == "UDP":
        cmd.append("-sU")
    
    cmd = ["nmap", "-sS", "-Pn", domain, "-oX", "nmap_scan.xml"]
    
    asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
        ) => "nmap -sS -Pn <domain> -oX nmap_scan.xml"