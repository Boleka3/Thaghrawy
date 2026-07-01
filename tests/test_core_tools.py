import pytest

from core.tools import (
    ToolRegistry,
    _EXPLOIT_TOOL_NAMES,
    _RECON_TOOL_NAMES,
    _make_generate_report,
    _make_load_engagement_context,
    _make_save_finding,
    _make_save_technique,
    _make_shell_tool,
    build_default_registry,
    build_filtered_registry,
    generate_engagement_reports,
    http_request,
    parse_tool_output,
    schema_from_function,
)


# ── ToolRegistry ──


def test_register_and_get():
    registry = ToolRegistry()
    registry.register("greet", lambda name: f"hi {name}")
    tool = registry.get("greet")
    assert tool is not None
    assert tool.name == "greet"


def test_get_unknown_tool_returns_none():
    registry = ToolRegistry()
    assert registry.get("nope") is None


def test_names_and_schemas():
    registry = ToolRegistry()
    registry.register("a", lambda: None, description="does a")
    registry.register("b", lambda: None, description="does b")
    assert set(registry.names()) == {"a", "b"}
    schema_names = {s.name for s in registry.schemas()}
    assert schema_names == {"a", "b"}


@pytest.mark.anyio
async def test_execute_sync_handler():
    registry = ToolRegistry()
    registry.register("add", lambda a, b: a + b)
    result = await registry.execute("add", {"a": 1, "b": 2})
    assert result == 3


@pytest.mark.anyio
async def test_execute_async_handler():
    async def double(x):
        return x * 2

    registry = ToolRegistry()
    registry.register("double", double)
    result = await registry.execute("double", {"x": 5})
    assert result == 10


@pytest.mark.anyio
async def test_execute_unknown_tool_returns_error_dict():
    registry = ToolRegistry()
    result = await registry.execute("ghost", {})
    assert result == {"error": "Unknown tool: ghost"}


@pytest.mark.anyio
async def test_execute_handler_exception_is_caught():
    def boom():
        raise RuntimeError("kaboom")

    registry = ToolRegistry()
    registry.register("boom", boom)
    result = await registry.execute("boom", {})
    assert "error" in result
    assert "kaboom" in result["error"]


def test_tool_description_defaults_to_docstring_first_line():
    def handler(x: str) -> str:
        """First line.

        More detail.
        """
        return x

    registry = ToolRegistry()
    registry.register("handler", handler)
    assert registry.get("handler").description == "First line."


# ── schema_from_function ──


def test_schema_from_function_required_param_no_default():
    def fn(target: str):
        pass

    schema = schema_from_function(fn)
    assert schema["properties"]["target"] == {"type": "string"}
    assert schema["required"] == ["target"]


def test_schema_from_function_param_with_default_is_not_required():
    def fn(target: str, ports: str = ""):
        pass

    schema = schema_from_function(fn)
    assert "ports" not in schema["required"]
    assert "target" in schema["required"]


def test_schema_from_function_list_param_gets_array_type():
    def fn(domains: list[str] = None):
        pass

    schema = schema_from_function(fn)
    assert schema["properties"]["domains"]["type"] == "array"
    assert schema["properties"]["domains"]["items"] == {"type": "string"}


def test_schema_from_function_skips_self_args_kwargs():
    def fn(self, *args, real_param: str = "x", **kwargs):
        pass

    schema = schema_from_function(fn)
    assert set(schema["properties"].keys()) == {"real_param"}


# ── memory-backed tool factories ──


def test_persist_finding_increments_engagement_count(tmp_memory, tmp_engagements, make_finding):
    from core.tools import persist_finding

    engagement = tmp_engagements.create(name="E", target="https://e.com")
    persist_finding(tmp_memory, make_finding(engagement_id=engagement.id), tmp_engagements)
    persist_finding(tmp_memory, make_finding(id="f2", engagement_id=engagement.id), tmp_engagements)

    assert tmp_engagements.get(engagement.id).findings_count == 2
    assert len(tmp_memory.load_engagement_findings(engagement.id)) == 2


def test_make_save_finding_increments_count(tmp_memory, tmp_engagements):
    engagement = tmp_engagements.create(name="E", target="https://e.com")
    save_finding = _make_save_finding(tmp_memory, tmp_engagements)
    save_finding({
        "title": "X", "severity": "low", "vuln_type": "Misc", "description": "d",
        "reproduction_steps": "r", "technique_used": "t", "target": "x",
        "engagement_id": engagement.id,
    })
    assert tmp_engagements.get(engagement.id).findings_count == 1


def test_make_save_finding_persists_and_returns_id(tmp_memory):
    save_finding = _make_save_finding(tmp_memory)
    result = save_finding({
        "title": "XSS in search box",
        "severity": "medium",
        "vuln_type": "XSS",
        "description": "Reflected XSS",
        "reproduction_steps": "GET /search?q=<script>",
        "technique_used": "manual",
        "target": "https://example.com/search",
        "engagement_id": "eng-1",
    })
    assert result["status"] == "saved"
    loaded = tmp_memory.load_engagement_findings("eng-1")
    assert len(loaded) == 1
    assert loaded[0]["id"] == result["id"]


def test_make_save_finding_defaults_id_and_date(tmp_memory):
    save_finding = _make_save_finding(tmp_memory)
    result = save_finding({
        "title": "X", "severity": "low", "vuln_type": "Misc", "description": "d",
        "reproduction_steps": "r", "technique_used": "t", "target": "x", "engagement_id": "eng-1",
    })
    assert result["id"]
    loaded = tmp_memory.load_engagement_findings("eng-1")
    assert loaded[0]["metadata"]["date"]


def test_make_save_technique_persists_and_returns_id(tmp_memory):
    save_technique = _make_save_technique(tmp_memory)
    result = save_technique({
        "name": "Tamper bypass",
        "description": "Bypass WAF with sqlmap tamper scripts",
        "platform": "web",
        "engagement_id": "eng-1",
    })
    assert result["status"] == "saved"
    hits = tmp_memory.search_techniques("bypass a WAF")
    assert any(h["id"] == result["id"] for h in hits)


def test_make_load_engagement_context_returns_findings(tmp_memory, make_finding):
    tmp_memory.add_finding(make_finding(id="f-1", engagement_id="eng-1"))
    load_context = _make_load_engagement_context(tmp_memory)
    result = load_context("eng-1")
    assert len(result["findings"]) == 1


def test_generate_engagement_reports_unknown_engagement_returns_error(tmp_memory):
    result = generate_engagement_reports(tmp_memory, "does-not-exist")
    assert "error" in result


def test_generate_engagement_reports_builds_both_report_types(tmp_memory, make_finding, tmp_engagements):
    # generate_engagement_reports() constructs its own EngagementManager()
    # pointed at config.ENGAGEMENTS_DIR, which conftest.py already redirects
    # to the session tmp dir - tmp_engagements (function-scoped, its own
    # tmp_path) points elsewhere, so the engagement has to be created through
    # config.ENGAGEMENTS_DIR directly for generate_engagement_reports to find it.
    from engagements.manager import EngagementManager

    engagement = EngagementManager().create(name="Acme", target="https://acme.example.com")
    tmp_memory.add_finding(make_finding(id="f-1", engagement_id=engagement.id))

    result = generate_engagement_reports(tmp_memory, engagement.id)
    assert "technical" in result and "executive" in result
    assert "pdf" in result["technical"]
    assert "pdf" in result["executive"]


def test_make_generate_report_factory_delegates(tmp_memory, make_finding):
    # Same EngagementManager() default-base-dir caveat as the test above.
    from engagements.manager import EngagementManager

    engagement = EngagementManager().create(name="Acme", target="https://acme.example.com")
    tmp_memory.add_finding(make_finding(id="f-1", engagement_id=engagement.id))

    generate_report = _make_generate_report(tmp_memory)
    result = generate_report(engagement.id)
    assert "technical" in result and "executive" in result


# ── shell tool / guardrails integration ──


def test_make_shell_tool_runs_harmless_command():
    shell = _make_shell_tool("eng-1")
    result = shell("echo hi")
    assert result["status"] == "success"
    assert "hi" in result["stdout"]


def test_make_shell_tool_blocks_dangerous_command_without_force():
    shell = _make_shell_tool("eng-1")
    result = shell("rm -rf /", force=False)
    assert result["status"] == "blocked"


# ── generic tools ──


def test_parse_tool_output_dispatches_correctly():
    result = parse_tool_output("nmap", "22/tcp open ssh\n")
    assert result["findings"] == ["22/tcp open ssh"]


def test_http_request_signature_exists():
    assert callable(http_request)


def test_http_request_returns_structured_error_on_connection_failure(monkeypatch):
    # A dead target / DNS miss must come back as a structured error, not a raised
    # exception the registry would surface as a "raised: ..." plumbing bug.
    import httpx

    def boom(self, *a, **k):
        raise httpx.ConnectError("Name or service not known")

    monkeypatch.setattr(httpx.Client, "request", boom)
    result = http_request(url="http://dead-target:9999", method="GET")
    assert result["status"] == "error"
    assert "failed" in result["error"]


# ── registry wiring ──


def test_build_default_registry_registers_every_expected_tool(tmp_memory):
    registry = build_default_registry(tmp_memory, "eng-1")
    expected = set(_RECON_TOOL_NAMES) | set(_EXPLOIT_TOOL_NAMES) | {
        "generate_report", "search_memory", "save_finding", "save_technique",
        "load_engagement_context", "shell", "http_request", "parse_tool_output",
    }
    assert set(registry.names()) == expected


def test_build_default_registry_marks_dangerous_tools_correctly(tmp_memory):
    registry = build_default_registry(tmp_memory, "eng-1")
    assert registry.get("shell").dangerous is True
    assert registry.get("sqlmap_scan").dangerous is True
    assert registry.get("nikto_scan").dangerous is True
    assert registry.get("hydra_bruteforce").dangerous is True
    assert registry.get("search_memory").dangerous is False
    assert registry.get("nmap_scan").dangerous is False


def test_build_filtered_registry_recon_only_excludes_exploit_tools(tmp_memory):
    registry = build_filtered_registry("recon_only", tmp_memory, "eng-1")
    names = set(registry.names())
    assert not names & set(_EXPLOIT_TOOL_NAMES)
    assert set(_RECON_TOOL_NAMES) <= names
    assert "save_finding" in names and "shell" in names


def test_build_filtered_registry_full_analysis_includes_everything(tmp_memory):
    registry = build_filtered_registry("full_analysis", tmp_memory, "eng-1")
    assert set(_EXPLOIT_TOOL_NAMES) <= set(registry.names())
