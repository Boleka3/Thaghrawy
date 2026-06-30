"""Unified tool registry. Every tool the agent can call - MCP recon/exploit/
report tools, memory tools, and generic shell/http/parsing tools - is
registered here. core/agent.py never imports mcp/ or memory/ directly; it
only talks to a ToolRegistry.
"""
from __future__ import annotations

import asyncio
import inspect
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Optional, get_type_hints

import config
from core.llm import ToolSchema
from memory.store import MemoryStore

if TYPE_CHECKING:
    from engagements.manager import EngagementManager
    from memory.schemas import Finding

_TYPE_MAP = {str: "string", int: "integer", float: "number", bool: "boolean", list: "array", dict: "object"}


def schema_from_function(func: Callable[..., Any]) -> dict[str, Any]:
    """Best-effort JSON Schema derived from a function's signature."""
    sig = inspect.signature(func)
    try:
        hints = get_type_hints(func)
    except Exception:
        hints = {}

    properties: dict[str, Any] = {}
    required: list[str] = []
    for name, param in sig.parameters.items():
        if name in ("self", "kwargs", "args"):
            continue
        hint = hints.get(name, str)
        origin = getattr(hint, "__origin__", hint)
        json_type = _TYPE_MAP.get(origin, "string")
        prop: dict[str, Any] = {"type": json_type}
        if json_type == "array":
            prop["items"] = {"type": "string"}
        properties[name] = prop
        if param.default is inspect.Parameter.empty:
            required.append(name)

    return {"type": "object", "properties": properties, "required": required}


@dataclass
class Tool:
    name: str
    handler: Callable[..., Any]
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    dangerous: bool = False

    def __post_init__(self) -> None:
        if not self.description:
            doc = (inspect.getdoc(self.handler) or "").strip()
            self.description = doc.split("\n")[0] if doc else self.name
        if not self.parameters:
            self.parameters = schema_from_function(self.handler)

    def schema(self) -> ToolSchema:
        return ToolSchema(name=self.name, description=self.description, parameters=self.parameters)


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(
        self,
        name: str,
        handler: Callable[..., Any],
        description: str = "",
        parameters: Optional[dict[str, Any]] = None,
        dangerous: bool = False,
    ) -> None:
        self._tools[name] = Tool(
            name=name,
            handler=handler,
            description=description,
            parameters=parameters or {},
            dangerous=dangerous,
        )

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return list(self._tools.keys())

    def schemas(self) -> list[ToolSchema]:
        return [t.schema() for t in self._tools.values()]

    async def execute(self, name: str, arguments: dict[str, Any]) -> Any:
        tool = self.get(name)
        if tool is None:
            return {"error": f"Unknown tool: {name}"}
        try:
            if inspect.iscoroutinefunction(tool.handler):
                result = await tool.handler(**arguments)
            else:
                # Most handlers are blocking (subprocess, httpx, PDF render).
                # Run them off the event loop so one slow tool can't stall the
                # chat WebSocket / token streaming for every connected client.
                result = await asyncio.to_thread(tool.handler, **arguments)
            if inspect.isawaitable(result):
                result = await result
            return result
        except Exception as e:
            return {"error": f"Tool '{name}' raised: {e}"}


# ──────────────────────────────────────────────
#   Memory tools
# ──────────────────────────────────────────────


def _make_search_memory(memory: MemoryStore):
    def search_memory(query: str, collection: str = "both", top_k: int = 3) -> dict[str, Any]:
        """Semantic search over past findings and/or techniques across all engagements."""
        if collection == "findings":
            return {"findings": memory.search_findings(query, top_k=top_k)}
        if collection == "techniques":
            return {"techniques": memory.search_techniques(query, top_k=top_k)}
        return memory.search_context(query, top_k=top_k)

    return search_memory


def persist_finding(
    memory: MemoryStore,
    finding: "Finding",
    manager: Optional["EngagementManager"] = None,
) -> None:
    """Single write path for a confirmed finding: store it in memory AND bump
    the engagement's findings_count. Both the agent's save_finding tool and the
    POST /api/findings route call this so the count can't diverge between them.
    """
    from engagements.manager import EngagementManager

    memory.add_finding(finding)
    (manager or EngagementManager()).increment_findings_count(finding.engagement_id)


def _make_save_finding(memory: MemoryStore, manager: Optional["EngagementManager"] = None):
    def save_finding(finding: dict[str, Any]) -> dict[str, Any]:
        """Persist a new vulnerability finding to long-term memory. `finding`
        must match the Finding schema (title, severity, vuln_type, description,
        reproduction_steps, technique_used, target, engagement_id, tags). Also
        include, when you can judge them at confirmation time: cvss_score
        (float), affected_component (the specific service/endpoint/library),
        business_impact (one line on what exploitation means for the business -
        e.g. data exposure, downtime, compliance), and remediation (a concrete
        fix). These feed the executive report, so skip the jargon in
        business_impact."""
        from memory.schemas import Finding

        finding.setdefault("id", str(uuid.uuid4()))
        finding.setdefault("date", datetime.now(timezone.utc).date().isoformat())
        record = Finding(**finding)
        persist_finding(memory, record, manager)
        return {"status": "saved", "id": record.id}

    return save_finding


def _make_save_technique(memory: MemoryStore):
    def save_technique(technique: dict[str, Any]) -> dict[str, Any]:
        """Persist a new attack technique to long-term memory. `technique`
        must match the Technique schema (name, description, works_against,
        platform, engagement_id, tags)."""
        from memory.schemas import Technique

        technique.setdefault("id", str(uuid.uuid4()))
        technique.setdefault("date", datetime.now(timezone.utc).date().isoformat())
        record = Technique(**technique)
        memory.add_technique(record)
        return {"status": "saved", "id": record.id}

    return save_technique


def _make_load_engagement_context(memory: MemoryStore):
    def load_engagement_context(engagement_id: str) -> dict[str, Any]:
        """Load all findings recorded so far for a given engagement."""
        return {"findings": memory.load_engagement_findings(engagement_id)}

    return load_engagement_context


def generate_engagement_reports(memory: MemoryStore, engagement_id: str) -> dict[str, Any]:
    """Build a technical report and an executive report for an engagement
    directly from its saved findings, and render both to .md/.pdf. Shared by
    the agent's generate_report tool and the /api/engagements/{id}/reports
    HTTP route so there's exactly one place this logic lives."""
    from engagements.manager import EngagementManager
    from mcp_servers.report_server import render_to_files
    from reporting.builder import build_executive_report, build_technical_report

    engagement = EngagementManager().get(engagement_id)
    if engagement is None:
        return {"error": f"Unknown engagement_id: {engagement_id}"}

    findings = memory.load_engagement_findings_as_models(engagement_id)
    prefix_suffix = engagement_id[:8]
    return {
        "technical": render_to_files(
            build_technical_report(engagement, findings), f"technical_report_{prefix_suffix}"
        ),
        "executive": render_to_files(
            build_executive_report(engagement, findings), f"executive_report_{prefix_suffix}"
        ),
    }


def _make_generate_report(memory: MemoryStore):
    def generate_report(engagement_id: str) -> dict[str, Any]:
        """Generate both a technical report (full evidence and reproduction
        steps, for developers) and an executive report (business impact and
        priority, for management) for this engagement, built directly from
        its saved findings - no need to write report content by hand."""
        return generate_engagement_reports(memory, engagement_id)

    return generate_report


# ──────────────────────────────────────────────
#   Generic tools
# ──────────────────────────────────────────────


def _make_shell_tool(engagement_id: str):
    def shell(command: str, force: bool = False) -> dict[str, Any]:
        """Execute a shell command. Logged with timestamp + engagement context.
        Destructive patterns (rm -rf, mkfs, dd, etc.) are blocked unless
        force=True, and may still require human confirmation."""
        import subprocess

        import guardrails

        allowed, reason = guardrails.Guardrails.check_shell_command(command, force=force)
        guardrails.Guardrails.log_shell_command(command, engagement_id, allowed, reason)
        if not allowed:
            return {"status": "blocked", "reason": reason}
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=config.MAX_SHELL_TIMEOUT
            )
            return {
                "status": "success" if result.returncode == 0 else "failed",
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-2000:],
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": f"Command timed out after {config.MAX_SHELL_TIMEOUT}s"}

    return shell


def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    body: Optional[str] = None,
) -> dict[str, Any]:
    """Make an HTTP request and return status code, headers, and body (truncated)."""
    import httpx

    with httpx.Client(timeout=30, follow_redirects=True) as client:
        response = client.request(method.upper(), url, headers=headers or {}, content=body)
    return {"status_code": response.status_code, "headers": dict(response.headers), "body": response.text[:4000]}


def parse_tool_output(tool_name: str, raw_output: str) -> dict[str, Any]:
    """Filter/truncate raw tool output (nmap/sqlmap/nikto/generic) for context efficiency."""
    from output_filter import ToolOutputFilter

    return ToolOutputFilter.apply_filter(tool_name, raw_output)


# ──────────────────────────────────────────────
#   Registry factory
# ──────────────────────────────────────────────

_RECON_TOOL_NAMES = (
    "amass_scan", "subfinder_scan", "httpx_scan", "ffuf_fuzz", "gobuster_scan",
    "katana_crawl", "nuclei_scan", "whois_lookup", "web_tech_detect", "assetfinder_scan",
    "naabu_scan", "dnsx_scan", "nmap_scan", "wpscan_scan", "testssl_scan", "wafw00f_scan",
    "searchsploit_lookup", "arjun_scan", "masscan_scan", "enum4linux_scan",
    "list_workspace", "read_file", "grep_workspace",
    # Kill chain — Delivery / C2
    "upload_test", "ssrf_test",
)
_EXPLOIT_TOOL_NAMES = (
    "sqlmap_scan", "nikto_scan", "hydra_bruteforce",
    # Kill chain — Post-Exploitation
    "linux_privesc_check", "credential_search",
)


def build_default_registry(
    memory: MemoryStore, engagement_id: str, include_exploit_tools: bool = True
) -> ToolRegistry:
    from engagements.manager import EngagementManager

    registry = ToolRegistry()
    manager = EngagementManager()

    from mcp_servers import recon_server
    for name in _RECON_TOOL_NAMES:
        registry.register(name, getattr(recon_server, name))

    if include_exploit_tools:
        from mcp_servers import exploit_server
        for name in _EXPLOIT_TOOL_NAMES:
            registry.register(name, getattr(exploit_server, name), dangerous=True)

    registry.register("generate_report", _make_generate_report(memory))

    registry.register("search_memory", _make_search_memory(memory))
    registry.register("save_finding", _make_save_finding(memory, manager))
    registry.register("save_technique", _make_save_technique(memory))
    registry.register("load_engagement_context", _make_load_engagement_context(memory))

    registry.register("shell", _make_shell_tool(engagement_id), dangerous=True)
    registry.register("http_request", http_request)
    registry.register("parse_tool_output", parse_tool_output)

    return registry


def build_filtered_registry(mode: str, memory: MemoryStore, engagement_id: str) -> ToolRegistry:
    """Thin wrapper over build_default_registry() for the FR-01 recon-only vs
    full-analysis engagement mode - keeps a single registry-construction path
    rather than maintaining two."""
    return build_default_registry(memory, engagement_id, include_exploit_tools=mode != "recon_only")
