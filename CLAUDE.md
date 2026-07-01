# CLAUDE.md — Thaghrawy

## What This Project Is
AI-powered pentesting assistant with persistent cross-engagement memory.
Graduation project — 6 developers, active development.

## Running the Project
```bash
pip install -r requirements.txt
cp .env.example .env        # Fill in your API keys
python main.py               # Starts FastAPI on port 8000
# Open http://localhost:8000 in browser
```

## Architecture at a Glance
- `main.py` → FastAPI app, serves frontend at `/`, API at `/api/`, chat WebSocket at `/ws/chat`
- `core/agent.py` → Main agent loop (tool-calling ReAct loop, not phase-based)
- `core/llm.py` → LLM abstraction (Anthropic / OpenAI / Ollama), normalized streaming events
- `core/tools.py` → Tool registry — all agent tools defined/wired here
- `core/context.py` → Context window trimming + tool-output truncation
- `memory/store.py` → ChromaDB interface — NEVER query ChromaDB directly, always go through this
- `memory/schemas.py` → Pydantic models for Finding, Technique, Engagement
- `memory/embeddings.py` → local sentence-transformers embedding wrapper
- `mcp_servers/` → MCP-style tool servers (recon/exploit/report) + `mcp_servers/tools/` wrappers.
  Named `mcp_servers/`, not `mcp/`, to avoid shadowing the installed `mcp` SDK package
  that `recon_server.py`/`exploit_server.py`/`report_server.py` themselves import.
  `report_server.py` only renders Markdown -> .md/.pdf (`render_to_files()`); it has no
  memory/engagement dependency.
- `reporting/builder.py` → Pure functions that turn an `Engagement` + its `Finding`s into
  the two report Markdown documents (technical / executive) — no I/O, no DB access.
- `engagements/manager.py` → Engagement lifecycle (JSON + markdown session logs)
- `benchmarks/` → Scoring harness for the four `Thaghrawy_Project.pdf` metrics —
  ESR (Exploit Success Rate, ≥0.70), AST (Average Steps per Task, from the agent's
  per-turn step counters), FP-rate (≤0.15), and Detection Rate (distinct OWASP
  Top-10 classes, 8/10) — evaluating engagement findings against known DVWA/Juice
  Shop categories. `benchmarks/scorer.py` is pure (returns a `BenchmarkResult`);
  `benchmarks/runner.py` is the I/O driver (`python -m benchmarks.runner <id>
  <target>`). See `benchmarks/README.md`
- `api/` → FastAPI routes and WebSocket streaming
- `frontend/` → Dark hacker UI (HTML/CSS/JS)
- `guardrails.py` → Safety filtering (dangerous shell patterns, JSON enforcement) — do not bypass
- `prompt_builder.py` → System prompt construction — always inject memory here

## Branch Map
| Branch | Developer | Owns |
|---|---|---|
| `main` | Protected | Production only — requires 2 approvals |
| `dev` | All | Integration — PR here first, requires 1 approval |
| `feat/agent-core` | Dev 1 | `core/` directory |
| `feat/memory-layer` | Dev 2 | `memory/` directory |
| `feat/engagements` | Dev 3 | `engagements/` directory |
| `feat/api` | Dev 4 | `api/` directory |
| `feat/frontend` | Dev 5 | `frontend/` directory |
| `feat/mcp-tools` | Dev 6 | `mcp_servers/` directory |

**Never push directly to `main` or `dev`. Always PR.**

## Code Rules
- Type hints on every function
- Pydantic models for all data structures
- All tool calls go through `core/tools.py`
- All memory operations go through `memory/store.py`
- Never hardcode API keys — use `.env` and `config.py`
- Shell commands must be logged — never bypass `guardrails.py`

## Adding a New LLM Provider
1. Add a class in `core/llm.py` implementing `BaseLLMProvider.stream()`
2. Add env vars to `.env.example` and `config.py`
3. Register it in `get_provider()`
4. Verify streaming + tool use work before merging

## Adding a New Agent Tool
1. Implement the handler function (sync or async) anywhere appropriate
2. Register it in `core/tools.py`'s `build_default_registry()` (or call `registry.register()`)
3. Update this file's tool list below

## Adding a New MCP Recon Tool
1. Add a wrapper module in `mcp_servers/tools/` using `mcp_servers/tools/_common.py`'s
   `run_command()` helper (gives you timeout + workspace persistence + JSON envelope for free).
   For host-oriented scanners, normalize the target with `_common.strip_url()` (drops a
   URL scheme/path) and, if the scanner does poor DNS resolution, `_common.resolve_host()`
   (resolves a bare hostname to an IP; passes IPs/CIDRs through) — naabu/masscan need this.
2. Import and register it with `@mcp.tool()` in `mcp_servers/recon_server.py`
3. Test the wrapper directly with `python -c "from mcp_servers.tools.X import Y; print(Y(...))"`

## Live Tool Smoke Test
Unit tests mock `subprocess.run`, so they never catch real-CLI bugs (wrong binary
name, URL-vs-host args, kwargs the LLM invents). `scripts/tool_smoke.py` closes that
gap: it drives **every** registered tool through the agent's own
`ToolRegistry.execute()` against a live, owned target (Juice Shop) and classifies each
result as OK / needs-review / BUG (uncaught exception, missing binary, bad kwarg).
Run it in the container after touching any tool wrapper:
```bash
docker compose exec -T agent python3 -m scripts.tool_smoke   # exit != 0 if any BUG
```
Empty results on an N/A target (no subdomains/TLS/SMB) are expected, not bugs.

## Current Agent Tools
- `search_memory`, `save_finding`, `save_technique`, `load_engagement_context` — memory
- `amass_scan`, `subfinder_scan`, `httpx_scan`, `ffuf_fuzz`, `gobuster_scan`, `katana_crawl`,
  `nuclei_scan`, `whois_lookup`, `web_tech_detect`, `assetfinder_scan`, `naabu_scan`, `dnsx_scan`,
  `nmap_scan`, `masscan_scan`, `wpscan_scan`, `testssl_scan`, `wafw00f_scan`,
  `searchsploit_lookup`, `arjun_scan`, `enum4linux_scan` — recon / vuln scanning
- `list_workspace`, `read_file`, `grep_workspace` — recon workspace utilities
- `sqlmap_scan`, `nikto_scan`, `hydra_bruteforce`, `dalfox_scan` (XSS),
  `wapiti_scan` (broad OWASP web sweep: XSS/SQLi/command-exec/file/SSRF) —
  exploitation (dangerous=True)
- `generate_report(engagement_id)` — builds both a technical report (full evidence/
  reproduction steps, for developers) and an executive report (business impact, for
  management) from the engagement's saved findings via `reporting/builder.py` +
  `mcp_servers/report_server.py`. Also reachable over HTTP at
  `POST /api/engagements/{id}/reports` (generate), `GET /api/engagements/{id}/reports`
  (list), `GET /api/reports/{filename}` (download) — see `api/routes/reports.py`.
- `shell` — generic shell execution (dangerous=True, logged, gated by `guardrails.py`)
- `http_request` — generic HTTP requests
- `parse_tool_output` — filter/truncate raw nmap/sqlmap/nikto/generic output

See `skills.py` for the methodology guidance (which tools map to which phase
of an engagement) injected into every system prompt via `prompt_builder.py`.

## Engagement Analysis Mode (FR-01)
Every `Engagement` has an `analysis_mode` field — `"full_analysis"` (default) or
`"recon_only"`. `api/deps.py`'s `_get_or_create_agent()` reads it and calls
`core/tools.py`'s `build_filtered_registry(mode, memory, engagement_id)`, which is a
thin wrapper over `build_default_registry(..., include_exploit_tools=...)`: a
`recon_only` engagement's agent never has `sqlmap_scan`/`nikto_scan`/`hydra_bruteforce`
registered, so it physically cannot attempt exploitation regardless of what the model
decides to do. Set at creation via `POST /api/engagements`'s `analysis_mode` field.

## Finding Risk Scoring
`Finding` carries both `cvss_score` and `dread_score` (1-10, agent-estimated
Damage/Reproducibility/Exploitability/Affected users/Discoverability) alongside
`affected_component`/`business_impact`/`remediation`. The executive report
(`reporting/builder.py`) sorts by severity first, `dread_score` as a tiebreaker within
the same severity band, and surfaces the DREAD score per finding for risk
prioritization.

## Embedding Model
Set `EMBEDDING_MODEL_PATH` in `.env` to a local snapshot directory to avoid re-downloading;
otherwise it resolves normally through sentence-transformers' HF Hub cache.

## Security Rules (Critical for a security tool)
- `guardrails.py` must be respected — it exists for legal/scope compliance
- The `shell` tool logs every command with timestamp + engagement context to
  `engagements/sessions/shell_command_log.jsonl`
- Dangerous patterns (rm -rf, dd, mkfs, format, fork bombs) require `force=True`,
  and may still need human confirmation if `DANGEROUS_COMMANDS_REQUIRE_CONFIRM=true`
- Never store raw credentials in ChromaDB or logs
- `.env` must never be committed — CI fails the build if one is found
- All reports in `reports/` may contain sensitive client data — handle accordingly
