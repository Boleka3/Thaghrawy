import json
import os
import re
from datetime import datetime, timezone

import config

LOG_PATH = os.path.join(config.ENGAGEMENTS_DIR, "shell_command_log.jsonl")

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


class Guardrails:
    @staticmethod
    def enforce_json(response_text: str) -> dict:
        """
        Strips markdown code fences and safely parses JSON.
        """
        match = re.search(r"\{.*\}", response_text, re.DOTALL)
        clean_text = match.group(0) if match else response_text
        try:
            return json.loads(clean_text)
        except json.JSONDecodeError as e:
            if "generate_report" in clean_text and "content_markdown" in clean_text:
                md_match = re.search(r'"content_markdown"\s*:\s*"(.*)', clean_text, re.DOTALL)
                if md_match:
                    content = md_match.group(1)
                    content = re.sub(r'"\s*\}*\s*$', '', content)
                    return {
                        "thought": "Recovered report from broken or truncated JSON.",
                        "tool_call": "generate_report",
                        "params": {"content_markdown": content},
                    }
            raise ValueError(f"Failed to parse LLM response as JSON: {str(e)}")

    @staticmethod
    def validate_findings(llm_json: dict, raw_tool_output: str) -> dict:
        """Checks if findings mentioned by the LLM actually exist in the tool output."""
        findings = llm_json.get("findings", [])
        validated = []
        for finding in findings:
            description = finding.get("description", "")
            finding["validated"] = description.lower() in raw_tool_output.lower()
            if not finding.get("validated"):
                finding["warning"] = "Finding not explicitly found in tool output evidence."
            finding["confidence"] = Guardrails.confidence_check(finding)
            validated.append(finding)
        llm_json["findings"] = validated
        return llm_json

    @staticmethod
    def confidence_check(finding: dict) -> str:
        """Helper to assign confidence level based on evidence."""
        return "high" if finding.get("evidence") else "low"

    @staticmethod
    def is_dangerous_shell_command(command: str) -> bool:
        return any(re.search(p, command, re.IGNORECASE) for p in DANGEROUS_PATTERNS)

    @staticmethod
    def check_shell_command(command: str, force: bool = False) -> tuple[bool, str]:
        """Gate for the agent's generic shell tool. Dangerous patterns are
        blocked unless force=True is explicitly passed by the caller."""
        if Guardrails.is_dangerous_shell_command(command):
            if force and not config.DANGEROUS_COMMANDS_REQUIRE_CONFIRM:
                return True, "Dangerous command allowed via force=True"
            if force and config.DANGEROUS_COMMANDS_REQUIRE_CONFIRM:
                return False, "Dangerous command requires human confirmation (DANGEROUS_COMMANDS_REQUIRE_CONFIRM=true)"
            return False, "Blocked: command matches a destructive pattern. Pass force=True to override."
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
