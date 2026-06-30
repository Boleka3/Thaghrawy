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
