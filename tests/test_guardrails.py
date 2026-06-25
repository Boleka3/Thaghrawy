import json

import pytest

import config
import guardrails
from guardrails import Guardrails


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "rm  -rf  /var",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda",
        "format c:",
        ":(){ :|:& };:",
        "echo hi > /dev/sda1",
        "shutdown -h now",
        "reboot",
    ],
)
def test_is_dangerous_shell_command_matches_destructive_patterns(command):
    assert Guardrails.is_dangerous_shell_command(command) is True


@pytest.mark.parametrize(
    "command",
    ["ls -la", "nmap -sV target.com", "curl https://example.com", "cat /etc/hostname"],
)
def test_is_dangerous_shell_command_allows_safe_commands(command):
    assert Guardrails.is_dangerous_shell_command(command) is False


def test_check_shell_command_allows_safe_command():
    allowed, reason = Guardrails.check_shell_command("ls -la")
    assert allowed is True
    assert reason == "ok"


def test_check_shell_command_blocks_dangerous_without_force():
    allowed, reason = Guardrails.check_shell_command("rm -rf /", force=False)
    assert allowed is False
    assert "force=True" in reason


def test_check_shell_command_blocks_dangerous_with_force_when_confirm_required(monkeypatch):
    monkeypatch.setattr(config, "DANGEROUS_COMMANDS_REQUIRE_CONFIRM", True)
    allowed, reason = Guardrails.check_shell_command("rm -rf /", force=True)
    assert allowed is False
    assert "human confirmation" in reason


def test_check_shell_command_allows_dangerous_with_force_when_confirm_not_required(monkeypatch):
    monkeypatch.setattr(config, "DANGEROUS_COMMANDS_REQUIRE_CONFIRM", False)
    allowed, reason = Guardrails.check_shell_command("rm -rf /", force=True)
    assert allowed is True
    assert "force=True" in reason


def test_enforce_json_parses_clean_json():
    result = Guardrails.enforce_json('{"thought": "ok", "tool_call": "nmap_scan"}')
    assert result == {"thought": "ok", "tool_call": "nmap_scan"}


def test_enforce_json_strips_surrounding_text_and_fences():
    text = 'Here is my response:\n```json\n{"thought": "scanning"}\n```\nDone.'
    result = Guardrails.enforce_json(text)
    assert result == {"thought": "scanning"}


def test_enforce_json_recovers_truncated_generate_report_call():
    broken = (
        '{"thought": "wrapping up", "tool_call": "generate_report", '
        '"params": {"content_markdown": "# Report\\n\\nSome findings here'
    )
    result = Guardrails.enforce_json(broken)
    assert result["tool_call"] == "generate_report"
    assert "Some findings here" in result["params"]["content_markdown"]


def test_enforce_json_raises_on_unrecoverable_garbage():
    with pytest.raises(ValueError):
        Guardrails.enforce_json("not json at all and no braces")


def test_validate_findings_marks_validated_when_evidence_present():
    llm_json = {
        "findings": [
            {"description": "SQL injection found", "evidence": "sqlmap output"},
        ]
    }
    raw_output = "scan complete: SQL injection found in parameter id"
    result = Guardrails.validate_findings(llm_json, raw_output)
    assert result["findings"][0]["validated"] is True
    assert result["findings"][0]["confidence"] == "high"
    assert "warning" not in result["findings"][0]


def test_validate_findings_flags_unvalidated_and_low_confidence():
    llm_json = {"findings": [{"description": "a finding never mentioned in output"}]}
    result = Guardrails.validate_findings(llm_json, "totally unrelated raw tool output")
    assert result["findings"][0]["validated"] is False
    assert result["findings"][0]["warning"]
    assert result["findings"][0]["confidence"] == "low"


def test_confidence_check_high_with_evidence():
    assert Guardrails.confidence_check({"evidence": "some proof"}) == "high"


def test_confidence_check_low_without_evidence():
    assert Guardrails.confidence_check({}) == "low"


def test_log_shell_command_writes_jsonl_entry(tmp_path, monkeypatch):
    log_path = tmp_path / "shell_command_log.jsonl"
    monkeypatch.setattr(guardrails, "LOG_PATH", str(log_path))

    Guardrails.log_shell_command("ls -la", "eng-1", True, "ok")

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["command"] == "ls -la"
    assert entry["engagement_id"] == "eng-1"
    assert entry["allowed"] is True
    assert entry["reason"] == "ok"
    assert "timestamp" in entry


def test_log_shell_command_appends_multiple_entries(tmp_path, monkeypatch):
    log_path = tmp_path / "shell_command_log.jsonl"
    monkeypatch.setattr(guardrails, "LOG_PATH", str(log_path))

    Guardrails.log_shell_command("ls", "eng-1", True, "ok")
    Guardrails.log_shell_command("rm -rf /", "eng-1", False, "blocked")

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 2
