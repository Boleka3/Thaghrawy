"""Shared fixtures for mcp_servers/tools/* wrapper tests. Every wrapper
funnels its subprocess call through run_command()'s single
`_common.subprocess.run` choke point, so one fixture covers all of them."""
import json
from typing import Any

import httpx
import pytest

from mcp_servers.tools import _common


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(_common, "WORKSPACE_DIR", str(tmp_path))


class _FakeHttpxResponse:
    """Minimal httpx.Response stand-in for mocking."""

    def __init__(self, status_code: int = 200, text: str = "", headers: dict[str, str] | None = None):
        self.status_code = status_code
        self._text = text
        self.headers = httpx.Headers(headers or {})
        self.content = text.encode()

    @property
    def text(self) -> str:
        return self._text

    def json(self) -> Any:
        return json.loads(self._text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("mock error", request=None, response=self)


class _HttpxRecorder:
    def __init__(self):
        self.calls: list[dict[str, Any]] = []
        self._response = _FakeHttpxResponse()

    def set_response(self, status_code: int = 200, text: str = "", headers: dict[str, str] | None = None):
        self._response = _FakeHttpxResponse(status_code, text, headers)

    def get(self, url: str, **kwargs) -> _FakeHttpxResponse:
        self.calls.append({"method": "GET", "url": url, "kwargs": kwargs})
        return self._response

    def request(self, method: str, url: str, **kwargs) -> _FakeHttpxResponse:
        self.calls.append({"method": method.upper(), "url": url, "kwargs": kwargs})
        return self._response


@pytest.fixture
def fake_httpx(monkeypatch) -> _HttpxRecorder:
    recorder = _HttpxRecorder()
    monkeypatch.setattr("httpx.get", recorder.get)
    monkeypatch.setattr("httpx.request", recorder.request)
    return recorder


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
