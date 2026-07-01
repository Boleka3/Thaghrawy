import os

import pytest

from mcp_servers.tools import httpx as httpx_module
from mcp_servers.tools.httpx import _parse_httpx, httpx_scan

_SAMPLE_STDOUT = "https://example.com [200] [Apache]\nhttps://api.example.com [200] [nginx]\n"


@pytest.fixture(autouse=True)
def patch_httpx_workspace_dir(tmp_path, monkeypatch):
    # httpx.py does `from ._common import WORKSPACE_DIR`, binding its own
    # module-level name at import time - patching _common.WORKSPACE_DIR
    # (the isolated_workspace autouse fixture) doesn't reach that copy, so
    # it needs patching here too for file-path resolution to land in tmp_path.
    monkeypatch.setattr(httpx_module, "WORKSPACE_DIR", str(tmp_path))


def test_httpx_scan_requires_file_or_domains():
    result = httpx_scan()
    assert result["status"] == "error"
    assert "Provide either" in result["error"]


def test_httpx_scan_missing_file_returns_error():
    result = httpx_scan(file="does-not-exist.txt")
    assert result["status"] == "error"
    assert "Input file not found" in result["error"]


def test_httpx_scan_with_existing_workspace_file(fake_subprocess, tmp_path):
    (tmp_path / "domains.txt").write_text("example.com\n")
    fake_subprocess.stdout = _SAMPLE_STDOUT
    result = httpx_scan(file="domains.txt")
    assert result["status"] == "success"
    cmd = fake_subprocess.last_call
    # ProjectDiscovery binary is `httpx-toolkit` on Kali/Docker, `httpx` on bare metal.
    assert cmd[0] in ("httpx", "httpx-toolkit")
    assert cmd[cmd.index("-l") + 1] == str(tmp_path / "domains.txt")


def test_httpx_scan_prefers_projectdiscovery_binary(fake_subprocess, tmp_path, monkeypatch):
    # When httpx-toolkit exists it must be chosen over the venv Python `httpx`
    # CLI (which has no -l and errored in the nisc.coop run).
    (tmp_path / "domains.txt").write_text("example.com\n")
    fake_subprocess.stdout = _SAMPLE_STDOUT
    monkeypatch.setattr(
        httpx_module.shutil, "which",
        lambda name: "/usr/bin/httpx-toolkit" if name == "httpx-toolkit" else None,
    )
    httpx_scan(file="domains.txt")
    assert fake_subprocess.last_call[0].endswith("httpx-toolkit")


def test_httpx_scan_with_inline_domains_writes_workspace_file(fake_subprocess, tmp_path):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    result = httpx_scan(domains=["example.com", "api.example.com"])
    assert result["status"] == "success"
    cmd = fake_subprocess.last_call
    written_path = cmd[cmd.index("-l") + 1]
    assert os.path.isfile(written_path)
    assert "example.com" in open(written_path).read()


def test_parse_httpx_extracts_alive_hosts():
    parsed = _parse_httpx(_SAMPLE_STDOUT)
    assert parsed["alive_count"] == 2
    assert parsed["hosts"][0] == "https://example.com [200] [Apache]"


def test_parse_httpx_handles_empty_output():
    parsed = _parse_httpx("")
    assert parsed["alive_count"] == 0
