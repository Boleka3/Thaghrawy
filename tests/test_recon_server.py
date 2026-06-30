"""Tests for mcp_servers/recon_server.py - both the logic that lives only
here (inline tools web_tech_detect/assetfinder_scan/naabu_scan/dnsx_scan,
and the workspace utilities) and a delegation smoke test across every
@mcp.tool() wrapper that forwards to mcp_servers/tools/*.py."""
from __future__ import annotations

import json

import pytest

from mcp_servers import recon_server
from mcp_servers.recon_server import (
    _parse_assetfinder,
    _parse_dnsx,
    _parse_naabu,
    _parse_whatweb,
    assetfinder_scan,
    dnsx_scan,
    grep_workspace,
    list_workspace,
    naabu_scan,
    read_file,
    web_tech_detect,
)
from mcp_servers.tools import _common


class _FakeCompletedProcess:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(_common, "WORKSPACE_DIR", str(tmp_path))
    monkeypatch.setattr(recon_server, "WORKSPACE_DIR", str(tmp_path))


@pytest.fixture
def fake_subprocess(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return fake_run.result

    fake_run.result = _FakeCompletedProcess()
    fake_run.calls = calls
    monkeypatch.setattr(_common.subprocess, "run", fake_run)
    return fake_run


# ── inline tools: web_tech_detect / assetfinder_scan / naabu_scan / dnsx_scan ──


@pytest.mark.anyio
async def test_web_tech_detect_requires_target():
    result = json.loads(await web_tech_detect(target=""))
    assert result["status"] == "error"


@pytest.mark.anyio
async def test_web_tech_detect_builds_expected_argv(fake_subprocess):
    fake_subprocess.result = _FakeCompletedProcess(stdout="Apache[2.4.25]\nPHP[7.4]\n")
    await web_tech_detect(target="https://example.com")
    assert fake_subprocess.calls[-1] == ["whatweb", "--color=never", "https://example.com", "-v"]


def test_parse_whatweb_extracts_technology_lines():
    parsed = _parse_whatweb("https://example.com [200]\nApache: 2.4.25\nPHP: 7.4\n")
    assert parsed["technologies"] == ["Apache: 2.4.25", "PHP: 7.4"]


@pytest.mark.anyio
async def test_assetfinder_scan_requires_domain():
    result = json.loads(await assetfinder_scan(domain=""))
    assert result["status"] == "error"


@pytest.mark.anyio
async def test_assetfinder_scan_builds_expected_argv(fake_subprocess):
    fake_subprocess.result = _FakeCompletedProcess(stdout="api.example.com\n")
    await assetfinder_scan(domain="example.com")
    assert fake_subprocess.calls[-1] == ["assetfinder", "--subs-only", "example.com"]


def test_parse_assetfinder_dedupes_and_sorts():
    parsed = _parse_assetfinder("b.example.com\na.example.com\na.example.com\n")
    assert parsed["assets"] == ["a.example.com", "b.example.com"]
    assert parsed["asset_count"] == 2


@pytest.mark.anyio
async def test_naabu_scan_requires_target():
    result = json.loads(await naabu_scan(target=""))
    assert result["status"] == "error"


@pytest.mark.anyio
async def test_naabu_scan_with_explicit_ports(fake_subprocess):
    fake_subprocess.result = _FakeCompletedProcess(stdout="10.0.0.1:22\n")
    await naabu_scan(target="10.0.0.1", ports="22,80")
    cmd = fake_subprocess.calls[-1]
    assert cmd[:3] == ["naabu", "-host", "10.0.0.1"]
    assert "-p" in cmd and cmd[cmd.index("-p") + 1] == "22,80"
    assert "-top-ports" not in cmd


@pytest.mark.anyio
async def test_naabu_scan_default_uses_top_ports(fake_subprocess):
    fake_subprocess.result = _FakeCompletedProcess(stdout="")
    await naabu_scan(target="10.0.0.1")
    cmd = fake_subprocess.calls[-1]
    assert "-top-ports" in cmd and cmd[cmd.index("-top-ports") + 1] == "100"


def test_parse_naabu_extracts_ports_and_hosts():
    parsed = _parse_naabu("10.0.0.1:22\n10.0.0.1:80\n10.0.0.2:22\n")
    assert parsed["open_port_count"] == 2
    assert parsed["ports"] == [22, 80]


@pytest.mark.anyio
async def test_dnsx_scan_requires_target_or_list_file():
    result = json.loads(await dnsx_scan())
    assert result["status"] == "error"


@pytest.mark.anyio
async def test_dnsx_scan_with_target_builds_expected_argv(fake_subprocess):
    fake_subprocess.result = _FakeCompletedProcess(stdout="example.com. A 1.2.3.4\n")
    await dnsx_scan(target="example.com", record_type="a")
    cmd = fake_subprocess.calls[-1]
    assert "-d" in cmd and cmd[cmd.index("-d") + 1] == "example.com"
    assert "-a" in cmd


@pytest.mark.anyio
async def test_dnsx_scan_with_list_file_uses_dash_l(fake_subprocess):
    fake_subprocess.result = _FakeCompletedProcess(stdout="")
    await dnsx_scan(list_file="domains.txt")
    cmd = fake_subprocess.calls[-1]
    assert "-l" in cmd and cmd[cmd.index("-l") + 1] == "domains.txt"


def test_parse_dnsx_returns_record_lines():
    parsed = _parse_dnsx("example.com. A 1.2.3.4\napi.example.com. A 1.2.3.5\n")
    assert parsed["record_count"] == 2


# ── workspace utilities ──


@pytest.mark.anyio
async def test_list_workspace_lists_saved_files(tmp_path):
    (tmp_path / "scan1.txt").write_text("data")
    (tmp_path / "scan2.txt").write_text("more data")
    result = json.loads(await list_workspace())
    assert result["status"] == "success"
    assert result["file_count"] == 2
    names = {f["filename"] for f in result["files"]}
    assert names == {"scan1.txt", "scan2.txt"}


@pytest.mark.anyio
async def test_read_file_returns_content_and_line_count(tmp_path):
    (tmp_path / "scan.txt").write_text("line1\nline2\nline3\n")
    result = json.loads(await read_file(filename="scan.txt"))
    assert result["status"] == "success"
    assert result["total_lines"] == 3
    assert result["truncated"] is False
    assert "line1" in result["content"]


@pytest.mark.anyio
async def test_read_file_truncates_at_max_lines(tmp_path):
    (tmp_path / "scan.txt").write_text("\n".join(f"line{i}" for i in range(10)))
    result = json.loads(await read_file(filename="scan.txt", max_lines=3))
    assert result["returned_lines"] == 3
    assert result["truncated"] is True


@pytest.mark.anyio
async def test_read_file_missing_file_returns_error(tmp_path):
    result = json.loads(await read_file(filename="does-not-exist.txt"))
    assert result["status"] == "error"
    assert "not found" in result["error"]


@pytest.mark.anyio
async def test_read_file_blocks_path_traversal(tmp_path):
    result = json.loads(await read_file(filename="../../etc/passwd"))
    assert result["status"] == "error"
    assert "Access denied" in result["error"]


@pytest.mark.anyio
async def test_grep_workspace_finds_matches_across_files(tmp_path):
    (tmp_path / "a.txt").write_text("nothing interesting\nadmin found here\n")
    (tmp_path / "b.txt").write_text("also admin again\n")
    result = json.loads(await grep_workspace(pattern="admin"))
    assert result["status"] == "success"
    assert result["total_matches"] == 2


@pytest.mark.anyio
async def test_grep_workspace_scoped_to_single_file(tmp_path):
    (tmp_path / "a.txt").write_text("admin here\n")
    (tmp_path / "b.txt").write_text("admin there\n")
    result = json.loads(await grep_workspace(pattern="admin", filename="a.txt"))
    assert result["total_matches"] == 1
    assert result["matches"][0]["file"] == "a.txt"


@pytest.mark.anyio
async def test_grep_workspace_requires_pattern():
    result = json.loads(await grep_workspace(pattern=""))
    assert result["status"] == "error"


@pytest.mark.anyio
async def test_grep_workspace_blocks_path_traversal():
    result = json.loads(await grep_workspace(pattern="x", filename="../../etc/passwd"))
    assert result["status"] == "error"
    assert "Access denied" in result["error"]


# ── delegation smoke test: every @mcp.tool() wrapper still forwards
#    correctly to its underlying mcp_servers/tools/*.py function ──


@pytest.fixture
def wordlist(tmp_path):
    path = tmp_path / "wordlist.txt"
    path.write_text("admin\nlogin\n")
    return str(path)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "tool_name, kwargs",
    [
        ("amass_scan", {"domain": "example.com"}),
        ("subfinder_scan", {"domain": "example.com"}),
        ("katana_crawl", {"target": "https://example.com"}),
        ("nuclei_scan", {"target": "https://example.com"}),
        ("whois_lookup", {"domain": "example.com"}),
        ("nmap_scan", {"target": "example.com"}),
        ("wpscan_scan", {"target": "https://example.com"}),
        ("testssl_scan", {"target": "example.com"}),
        ("wafw00f_scan", {"target": "https://example.com"}),
        ("searchsploit_lookup", {"query": "Apache 2.4.49"}),
        ("arjun_scan", {"url": "https://example.com"}),
        ("masscan_scan", {"target": "10.0.0.0/24"}),
        ("enum4linux_scan", {"target": "10.0.0.5"}),
    ],
)
async def test_wrapper_delegates_and_returns_valid_json(fake_subprocess, tool_name, kwargs):
    fake_subprocess.result = _FakeCompletedProcess(stdout="", returncode=0)
    wrapper = getattr(recon_server, tool_name)
    raw = await wrapper(**kwargs)
    parsed = json.loads(raw)
    assert parsed["status"] == "success"
    assert "tool" in parsed
    assert fake_subprocess.calls, f"{tool_name} never invoked subprocess.run"


@pytest.mark.anyio
async def test_ffuf_fuzz_wrapper_delegates(fake_subprocess, wordlist):
    fake_subprocess.result = _FakeCompletedProcess(stdout="", returncode=0)
    raw = await recon_server.ffuf_fuzz(url="https://example.com/FUZZ", wordlist=wordlist)
    parsed = json.loads(raw)
    assert parsed["status"] == "success"


@pytest.mark.anyio
async def test_gobuster_scan_wrapper_delegates(fake_subprocess, wordlist):
    fake_subprocess.result = _FakeCompletedProcess(stdout="", returncode=0)
    raw = await recon_server.gobuster_scan(mode="dir", target="https://example.com", wordlist=wordlist)
    parsed = json.loads(raw)
    assert parsed["status"] == "success"


@pytest.mark.anyio
async def test_httpx_scan_wrapper_delegates(fake_subprocess):
    fake_subprocess.result = _FakeCompletedProcess(stdout="https://example.com [200]\n", returncode=0)
    raw = await recon_server.httpx_scan(domains=["example.com"])
    parsed = json.loads(raw)
    assert parsed["status"] == "success"
    assert parsed["alive_count"] == 1


# ── workspace path-traversal guard ──


def test_within_workspace_rejects_sibling_prefix(tmp_path):
    # str.startswith would wrongly accept '<ws>_evil'; commonpath must not.
    ws = str(tmp_path / "workspace")
    assert recon_server._within_workspace(ws + "/sub/file.txt", ws) is True
    assert recon_server._within_workspace(ws + "_evil/file.txt", ws) is False
