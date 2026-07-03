"""Test-wide setup. The env vars below MUST be set before `config` (or
anything importing it - memory.store, engagements.manager,
mcp_servers.tools._common, main) is imported anywhere in the test session,
since config.py reads them at module import time and immediately
os.makedirs()'s them. pytest always imports a directory's conftest.py
before collecting sibling test modules, so doing this at module level here
(not inside a fixture) guarantees it runs first."""
from __future__ import annotations

import os
import tempfile
import uuid
from typing import Any, AsyncIterator, Optional

_TMP_ROOT = os.path.join(tempfile.gettempdir(), f"thaghrawy-tests-{uuid.uuid4().hex[:8]}")
os.environ["REPORTS_DIR"] = os.path.join(_TMP_ROOT, "reports")
os.environ["ENGAGEMENTS_DIR"] = os.path.join(_TMP_ROOT, "engagements")
os.environ["WORKSPACE_DIR"] = os.path.join(_TMP_ROOT, "engagements", "_workspace")
os.environ["CHROMA_PERSIST_DIR"] = os.path.join(_TMP_ROOT, "chroma_db")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")

import pytest  # noqa: E402

from core.llm import BaseLLMProvider, ToolSchema  # noqa: E402
from core.tools import build_default_registry  # noqa: E402
from engagements.manager import EngagementManager  # noqa: E402
from memory.schemas import Engagement, Finding  # noqa: E402
from memory.store import MemoryStore  # noqa: E402


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def tmp_memory(tmp_path) -> MemoryStore:
    return MemoryStore(persist_dir=str(tmp_path / "chroma"))


@pytest.fixture
def tmp_engagements(tmp_path) -> EngagementManager:
    return EngagementManager(base_dir=str(tmp_path / "engagements"))


@pytest.fixture
def make_finding():
    def _make(**overrides: Any) -> Finding:
        fields = {
            "id": str(uuid.uuid4()),
            "title": "SQL Injection in login",
            "severity": "high",
            "vuln_type": "SQL Injection",
            "description": "The login form is vulnerable to boolean-based SQLi.",
            "reproduction_steps": "POST /login with username=' OR 1=1--",
            "technique_used": "sqlmap",
            "target": "https://example.com/login",
            "engagement_id": "eng-1",
            "date": "2026-06-01",
        }
        fields.update(overrides)
        return Finding(**fields)

    return _make


@pytest.fixture
def make_engagement():
    def _make(**overrides: Any) -> Engagement:
        fields = {
            "id": "eng-1",
            "name": "Acme Web App",
            "target": "https://acme.example.com",
            "scope": "acme.example.com",
            "start_date": "2026-06-01",
        }
        fields.update(overrides)
        return Engagement(**fields)

    return _make


class FakeLLMProvider(BaseLLMProvider):
    """Scripted provider for core/agent.py tests: yields exactly the events
    handed to it, ignoring the actual messages/system/tools it's called
    with. `scripts` is a list of event-lists, one per stream() call (each
    ReAct loop iteration calls stream() once)."""

    def __init__(self, scripts: list[list[dict[str, Any]]]):
        self._scripts = list(scripts)
        self.calls: list[dict[str, Any]] = []

    async def stream(
        self,
        messages: list[dict[str, Any]],
        system: str,
        tools: Optional[list[ToolSchema]] = None,
    ) -> AsyncIterator[dict[str, Any]]:
        self.calls.append({"messages": messages, "system": system, "tools": tools})
        if not self._scripts:
            raise AssertionError("FakeLLMProvider.stream() called more times than scripted")
        events = self._scripts.pop(0)
        for event in events:
            if isinstance(event, Exception):
                raise event
            yield event


@pytest.fixture
def fake_provider():
    return FakeLLMProvider


@pytest.fixture
def real_registry(tmp_memory):
    """A real ToolRegistry (memory tools backed by tmp_memory; recon/exploit
    tools registered as usual but never invoked by agent-loop tests)."""
    return build_default_registry(tmp_memory, "eng-1")


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    import config

    # Isolate per-test state: without this the app shares one engagements dir +
    # chroma store + reports dir for the whole session, so data (and, with
    # same-target dedup, engagements themselves) leak between tests. Patch the
    # config paths *before* the app's lifespan runs so BOTH the app.state
    # singletons and any internal default EngagementManager()/MemoryStore()
    # (e.g. report generation) agree on the same fresh per-test directories.
    monkeypatch.setattr(config, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
    monkeypatch.setattr(config, "WORKSPACE_DIR", str(tmp_path / "engagements" / "_workspace"))
    monkeypatch.setattr(config, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(config, "CHROMA_PERSIST_DIR", str(tmp_path / "chroma"))
    for _d in (config.ENGAGEMENTS_DIR, config.WORKSPACE_DIR, config.REPORTS_DIR):
        os.makedirs(_d, exist_ok=True)

    from fastapi.testclient import TestClient

    import main

    with TestClient(main.app) as client:
        yield client
