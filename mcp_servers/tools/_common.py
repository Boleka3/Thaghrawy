"""Shared helpers for MCP recon tool wrappers: sanitization, workspace
persistence, and a structured subprocess runner with a real timeout.

Every tool in mcp_servers/tools/ builds an argv list (never shell=True) and
calls run_command() so behavior - timeouts, output persistence, JSON
envelope shape - stays consistent across tools.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from datetime import datetime
from typing import Any, Callable, Optional

import config

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("mcp.tools")

WORKSPACE_DIR = config.WORKSPACE_DIR
os.makedirs(WORKSPACE_DIR, exist_ok=True)

# Security tool binaries (Go/system) must come before the venv on PATH so
# that wrappers like the Python httpx CLI don't shadow the projectdiscovery
# httpx binary. We prepend known go/system bin dirs here.
_TOOL_PATH_PREFIXES = [
    os.path.expanduser("~/go/bin"),
    "/usr/local/bin",
]
_env_path = os.environ.get("PATH", "")
_venv_bin = os.path.dirname(sys.executable)  # e.g. .venv/bin
# Build PATH: tool prefixes first, then everything except the venv bin
_non_venv = [p for p in _env_path.split(os.pathsep) if p != _venv_bin]
SUBPROCESS_ENV = {
    **os.environ,
    "PATH": os.pathsep.join(_TOOL_PATH_PREFIXES + [_venv_bin] + _non_venv),
}


def sanitize_input(value: Optional[str]) -> str:
    """Strip shell metacharacters. Commands are run via argv lists (no
    shell=True) so this isn't an injection fix - it's a defense-in-depth
    guard against malformed args reaching a binary's own arg parser."""
    if not value:
        return ""
    return re.sub(r"[;&|`$()]", "", value.strip())


def safe_filename(target: str, tool_name: str, ext: str = "txt") -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:80]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{tool_name}_{safe}_{timestamp}.{ext}"


def save_to_workspace(filename: str, content: str) -> str:
    filepath = os.path.join(WORKSPACE_DIR, filename)
    with open(filepath, "w") as f:
        f.write(content)
    logger.info(f"Saved results to {filepath}")
    return filepath


def _log_command(cmd: list[str]) -> None:
    """Audit-log every executed tool command (argv joined) to the shared
    shell command log, satisfying the project rule that all command
    execution is logged. Best-effort: a logging failure never aborts a scan.
    The engagement context is read from THAGHRAWY_ENGAGEMENT_ID when the
    agent process sets it (defaults to 'mcp-tools')."""
    try:
        import guardrails

        engagement_id = os.environ.get("THAGHRAWY_ENGAGEMENT_ID", "mcp-tools")
        guardrails.Guardrails.log_shell_command(
            " ".join(cmd), engagement_id, allowed=True, reason="mcp tool"
        )
    except Exception as exc:  # pragma: no cover - logging must never break a scan
        logger.warning(f"Failed to log command: {exc}")


def run_command(
    cmd: list[str],
    tool_name: str,
    target: str,
    parser: Optional[Callable[[str], dict[str, Any]]] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """Execute a command, persist full raw output to the workspace, and
    return a structured summary dict. Always bounded by `timeout` (defaults
    to config.RECON_TIMEOUT) so a hung scan can't block the agent forever.
    """
    timeout = timeout or config.RECON_TIMEOUT
    try:
        logger.info(f"Executing: {' '.join(cmd)} (timeout={timeout}s)")
        _log_command(cmd)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env=SUBPROCESS_ENV,
        )

        raw_output = result.stdout
        if result.stderr:
            raw_output += f"\n--- STDERR ---\n{result.stderr}"

        log_filename = safe_filename(target, tool_name)
        log_path = save_to_workspace(log_filename, raw_output)

        response: dict[str, Any] = {
            "status": "success" if result.returncode == 0 else "failed",
            "tool": tool_name,
            "target": target,
            "full_output_file": log_path,
        }

        if parser and result.returncode == 0:
            try:
                response.update(parser(result.stdout))
            except Exception as e:
                logger.warning(f"Parser error for {tool_name}: {e}")
                response["parse_error"] = str(e)
                lines = result.stdout.strip().split("\n")
                response["line_count"] = len(lines)
                response["preview"] = "\n".join(lines[:20])
        elif result.returncode != 0:
            stderr_lines = (result.stderr or "").strip().split("\n")
            response["error_preview"] = "\n".join(stderr_lines[:10])

        return response

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "tool": tool_name,
            "target": target,
            "error": f"Command timed out after {timeout}s",
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "tool": tool_name,
            "target": target,
            "error": f"Binary for '{tool_name}' not found on PATH",
        }
    except Exception as e:
        return {
            "status": "error",
            "tool": tool_name,
            "target": target,
            "error": str(e),
        }
