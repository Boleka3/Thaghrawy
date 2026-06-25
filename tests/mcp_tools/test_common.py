import subprocess

from mcp_servers.tools import _common
from mcp_servers.tools._common import run_command, safe_filename, sanitize_input, save_to_workspace


class _FakeCompletedProcess:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_sanitize_input_strips_shell_metacharacters():
    assert sanitize_input("foo;bar&baz|qux`x`$(y)") == "foobarbazquxxy"


def test_sanitize_input_strips_surrounding_whitespace():
    assert sanitize_input("  example.com  ") == "example.com"


def test_sanitize_input_handles_empty_and_none():
    assert sanitize_input("") == ""
    assert sanitize_input(None) == ""


def test_safe_filename_sanitizes_and_truncates_target():
    name = safe_filename("http://example.com/weird path?query=1", "nmap")
    assert name.startswith("nmap_")
    assert name.endswith(".txt")
    assert " " not in name
    assert "?" not in name


def test_safe_filename_respects_extension():
    name = safe_filename("example.com", "nuclei", ext="json")
    assert name.endswith(".json")


def test_save_to_workspace_writes_file_and_returns_path(tmp_path):
    path = save_to_workspace("out.txt", "hello world")
    assert path == str(tmp_path / "out.txt")
    assert (tmp_path / "out.txt").read_text() == "hello world"


def test_run_command_success_with_parser(monkeypatch, tmp_path):
    monkeypatch.setattr(
        _common.subprocess, "run", lambda *a, **k: _FakeCompletedProcess(stdout="22/tcp open ssh", returncode=0)
    )

    def parser(stdout):
        return {"parsed": stdout.strip()}

    result = run_command(["nmap", "-sV", "target"], "nmap", "target", parser=parser)
    assert result["status"] == "success"
    assert result["tool"] == "nmap"
    assert result["target"] == "target"
    assert result["parsed"] == "22/tcp open ssh"
    assert (tmp_path / result["full_output_file"].split("/")[-1]).is_file()


def test_run_command_failed_returncode_populates_error_preview(monkeypatch):
    monkeypatch.setattr(
        _common.subprocess, "run",
        lambda *a, **k: _FakeCompletedProcess(stdout="", stderr="binary not found\nusage: ...", returncode=1),
    )
    result = run_command(["badtool"], "badtool", "target")
    assert result["status"] == "failed"
    assert "binary not found" in result["error_preview"]


def test_run_command_without_parser_skips_parsing(monkeypatch):
    monkeypatch.setattr(_common.subprocess, "run", lambda *a, **k: _FakeCompletedProcess(stdout="raw", returncode=0))
    result = run_command(["echo", "hi"], "echo", "target")
    assert result["status"] == "success"
    assert "parsed" not in result


def test_run_command_parser_exception_falls_back_to_preview(monkeypatch):
    monkeypatch.setattr(
        _common.subprocess, "run",
        lambda *a, **k: _FakeCompletedProcess(stdout="line1\nline2\nline3", returncode=0),
    )

    def bad_parser(stdout):
        raise ValueError("boom")

    result = run_command(["tool"], "tool", "target", parser=bad_parser)
    assert result["status"] == "success"
    assert result["parse_error"] == "boom"
    assert result["line_count"] == 3
    assert "line1" in result["preview"]


def test_run_command_timeout(monkeypatch):
    def raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=30)

    monkeypatch.setattr(_common.subprocess, "run", raise_timeout)
    result = run_command(["nmap", "target"], "nmap", "target", timeout=30)
    assert result["status"] == "error"
    assert "timed out after 30s" in result["error"]


def test_run_command_binary_not_found(monkeypatch):
    def raise_not_found(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(_common.subprocess, "run", raise_not_found)
    result = run_command(["ghosttool", "target"], "ghosttool", "target")
    assert result["status"] == "error"
    assert "not found on PATH" in result["error"]


def test_run_command_generic_exception(monkeypatch):
    def raise_generic(*a, **k):
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(_common.subprocess, "run", raise_generic)
    result = run_command(["tool", "target"], "tool", "target")
    assert result["status"] == "error"
    assert result["error"] == "unexpected failure"


def test_run_command_uses_default_timeout_from_config(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["timeout"] = timeout
        return _FakeCompletedProcess(stdout="ok", returncode=0)

    monkeypatch.setattr(_common.subprocess, "run", fake_run)
    run_command(["tool"], "tool", "target")
    import config

    assert captured["timeout"] == config.RECON_TIMEOUT
