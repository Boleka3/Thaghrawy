import json
import os
import re
from datetime import datetime, timezone

import config

LOG_PATH = os.path.join(config.ENGAGEMENTS_DIR, "shell_command_log.jsonl")

# NOTE: this file intentionally contains only the live shell-safety surface
# (is_dangerous_shell_command / check_shell_command / log_shell_command). The
# old enforce_json / validate_findings / confidence_check helpers belonged to
# the pre-tool-calling JSON-pipeline architecture and were removed - the
# current ReAct loop (core/agent.py) never produces those JSON blobs.

# Patterns that can destroy data or the host filesystem. Anything matching
# requires force=True from the caller (see check_shell_command below).
DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bformat\b",
    r":\(\)\{.*\};:",  # fork bomb
    r">\s*/dev/sd[a-z]",
    r"\bshutdown\b",
    r"\breboot\b",
]

# Shell injection / escape patterns — commands that try to inject or bypass
# the intended argument structure. These require force=True.
INJECTION_PATTERNS = [
    r"(?<![\\])[;|&]",                     # command chaining: ; | &
    r"\bcurl\s+\S+\s*\|\s*(bash|sh|zsh)",  # pipe curl into shell
    r"\bbash\s+-c\b",                       # inline script execution
    r"\bpython\s+-c\b",
    r"\bperl\s+-e\b",
    r"\beval\b",
    r"\bexec\b",
    r"`[^`]+`",                             # backtick command substitution
    r"\$\s*\(",                             # $() command substitution
    r">\s*/dev/tcp/",                       # /dev/tcp reverse shell
    r"\\x[0-9a-fA-F]{2}",                  # hex-encoded shellcode in args
]


class Guardrails:
    @staticmethod
    def is_dangerous_shell_command(command: str) -> bool:
        return any(re.search(p, command, re.IGNORECASE) for p in DANGEROUS_PATTERNS)

    @staticmethod
    def has_injection_pattern(command: str) -> bool:
        """Check for shell injection / escape patterns. These don't always
        indicate malice — some legitimate commands use pipes — but they
        warrant a flag when combined with dangerous patterns."""
        return any(re.search(p, command, re.IGNORECASE) for p in INJECTION_PATTERNS)

    @staticmethod
    def check_shell_command(command: str, force: bool = False) -> tuple[bool, str]:
        """Gate for the agent's generic shell tool. Dangerous patterns are
        blocked unless force=True is explicitly passed by the caller.
        Also warns about injection patterns even when no destructive pattern
        is matched."""
        # Check dangerous destructive patterns first
        if Guardrails.is_dangerous_shell_command(command):
            if force and not config.DANGEROUS_COMMANDS_REQUIRE_CONFIRM:
                return True, "Dangerous command allowed via force=True"
            if force and config.DANGEROUS_COMMANDS_REQUIRE_CONFIRM:
                return False, "Dangerous command requires human confirmation (DANGEROUS_COMMANDS_REQUIRE_CONFIRM=true)"
            return False, "Blocked: command matches a destructive pattern. Pass force=True to override."
        # Warn about injection patterns even without destructive patterns
        if Guardrails.has_injection_pattern(command):
            return True, "Warning: command contains shell injection patterns (piped execution, eval, subshell)."
        return True, "ok"

    @staticmethod
    def log_shell_command(command: str, engagement_id: str, allowed: bool, reason: str = "") -> None:
        """Every shell command must be logged with timestamp + engagement context."""
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "engagement_id": engagement_id,
            "command": command,
            "allowed": allowed,
            "reason": reason,
        }
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
