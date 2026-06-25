"""Shared fixtures for mcp_servers/tools/* wrapper tests. Every wrapper
funnels its subprocess call through run_command()'s single
`_common.subprocess.run` choke point, so one fixture covers all of them."""
import pytest

from mcp_servers.tools import _common


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(_common, "WORKSPACE_DIR", str(tmp_path))


class _FakeCompletedProcess:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class _SubprocessRecorder:
    def __init__(self):
        self.stdout = ""
        self.stderr = ""
        self.returncode = 0
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        return _FakeCompletedProcess(self.stdout, self.stderr, self.returncode)

    @property
    def last_call(self) -> list[str]:
        return self.calls[-1]


@pytest.fixture
def fake_subprocess(monkeypatch) -> _SubprocessRecorder:
    recorder = _SubprocessRecorder()
    monkeypatch.setattr(_common.subprocess, "run", recorder)
    return recorder
