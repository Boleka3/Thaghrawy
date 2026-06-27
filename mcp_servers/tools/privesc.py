"""Kill Chain — Installation / Post-Exploitation: Linux privilege escalation recon."""
from __future__ import annotations

import subprocess
from typing import Any

from mcp_servers.tools._common import SUBPROCESS_ENV, safe_filename, save_to_workspace

_CHECKS = [
    ("whoami",        ["id"]),
    ("sudo_perms",    ["sudo", "-l", "-n"]),
    ("suid_bins",     ["find", "/", "-perm", "-4000", "-type", "f", "-ls"]),
    ("sgid_bins",     ["find", "/", "-perm", "-2000", "-type", "f", "-ls"]),
    ("writable_dirs", ["find", "/tmp", "/var/tmp", "/dev/shm", "-writable", "-type", "d"]),
    ("crontabs",      ["crontab", "-l"]),
    ("etc_cron",      ["ls", "-la", "/etc/cron.d", "/etc/cron.daily", "/etc/crontab"]),
    ("env_vars",      ["env"]),
    ("capabilities",  ["getcap", "-r", "/"]),
    ("passwd_shadow", ["ls", "-la", "/etc/passwd", "/etc/shadow"]),
]


def linux_privesc_check() -> dict[str, Any]:
    """
    Run common Linux privilege escalation recon commands after gaining a shell:
    id, sudo -l, SUID/SGID binaries, writable directories, crontabs,
    environment variables, file capabilities, /etc/passwd permissions.
    Returns structured findings for each check.
    """
    findings = []
    full_output = []

    for label, cmd in _CHECKS:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=20, env=SUBPROCESS_ENV
            )
            out = r.stdout.strip()
            err = r.stderr.strip()
            findings.append({
                "check": label,
                "status": "ok" if r.returncode == 0 else "error",
                "output": out[:2000] if out else err[:200],
            })
            full_output.append(f"=== {label} ===\n{out or err}")
        except FileNotFoundError:
            findings.append({"check": label, "status": "not_found", "output": f"{cmd[0]} not on PATH"})
        except Exception as e:
            findings.append({"check": label, "status": "error", "output": str(e)})

    interesting = [f for f in findings if f["status"] == "ok" and f["output"]]
    log_path = save_to_workspace(safe_filename("localhost", "privesc"), "\n\n".join(full_output))

    return {
        "status": "success",
        "tool": "linux_privesc_check",
        "summary": f"Completed {len(_CHECKS)} checks — {len(interesting)} returned output",
        "findings": findings,
        "full_output_file": log_path,
    }
