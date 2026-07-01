from mcp_servers.tools import testssl as testssl_module
from mcp_servers.tools.testssl import _parse_testssl
from mcp_servers.tools.testssl import testssl_scan as run_testssl_scan

_SAMPLE_STDOUT = """\
 SSLv2      not offered
 TLS1_2     offered
 TLS1_3     offered
 heartbleed not vulnerable (OK)
 poodle_ssl VULNERABLE, uses SSLv3
"""


def test_testssl_scan_requires_target():
    assert run_testssl_scan(target="")["status"] == "error"


def test_testssl_scan_fast_builds_expected_argv(fake_subprocess, monkeypatch):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    monkeypatch.setattr(testssl_module.shutil, "which", lambda name: None)  # neither on PATH -> fallback
    run_testssl_scan(target="example.com", fast=True)
    assert fake_subprocess.last_call == ["testssl.sh", "--color", "0", "--fast", "example.com"]


def test_testssl_scan_without_fast_omits_flag(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    run_testssl_scan(target="example.com", fast=False)
    assert "--fast" not in fake_subprocess.last_call


def test_testssl_scan_uses_plain_testssl_when_only_that_exists(fake_subprocess, monkeypatch):
    # Kali/Debian install the script on PATH as `testssl` (no .sh); the wrapper
    # errored with "Binary for 'testssl' not found" when it hardcoded testssl.sh.
    fake_subprocess.stdout = _SAMPLE_STDOUT
    monkeypatch.setattr(
        testssl_module.shutil, "which",
        lambda name: "/usr/bin/testssl" if name == "testssl" else None,
    )
    run_testssl_scan(target="example.com")
    assert fake_subprocess.last_call[0].endswith("testssl")
    assert not fake_subprocess.last_call[0].endswith("testssl.sh")


def test_testssl_scan_prefers_dotsh_binary_when_present(fake_subprocess, monkeypatch):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    monkeypatch.setattr(
        testssl_module.shutil, "which",
        lambda name: "/usr/bin/testssl.sh" if name == "testssl.sh" else None,
    )
    run_testssl_scan(target="example.com")
    assert fake_subprocess.last_call[0].endswith("testssl.sh")


def test_parse_testssl_extracts_protocols_and_vulnerabilities():
    parsed = _parse_testssl(_SAMPLE_STDOUT)
    assert parsed["protocols"]["TLS1_2"] == "offered"
    assert parsed["protocols"]["SSLv2"] == "not offered"
    assert len(parsed["vulnerabilities"]) == 1
    assert "poodle_ssl" in parsed["vulnerabilities"][0]


def test_parse_testssl_handles_no_vulnerabilities():
    parsed = _parse_testssl(" TLS1_3 offered\n heartbleed not vulnerable (OK)\n")
    assert parsed["vulnerabilities"] == []
