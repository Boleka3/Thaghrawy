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
- `engagements/manager.py` → Engagement lifecycle (JSON + markdown session logs)
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
   `run_command()` helper (gives you timeout + workspace persistence + JSON envelope for free)
2. Import and register it with `@mcp.tool()` in `mcp_servers/recon_server.py`
3. Test the wrapper directly with `python -c "from mcp_servers.tools.X import Y; print(Y(...))"`

## Current Agent Tools
- `search_memory`, `save_finding`, `save_technique`, `load_engagement_context` — memory
- `amass_scan`, `subfinder_scan`, `httpx_scan`, `ffuf_fuzz`, `gobuster_scan`, `katana_crawl`,
  `nuclei_scan`, `whois_lookup`, `web_tech_detect`, `assetfinder_scan`, `naabu_scan`, `dnsx_scan`,
  `nmap_scan`, `masscan_scan`, `wpscan_scan`, `testssl_scan`, `wafw00f_scan`,
  `searchsploit_lookup`, `arjun_scan`, `enum4linux_scan` — recon / vuln scanning
- `list_workspace`, `read_file`, `grep_workspace` — recon workspace utilities
- `sqlmap_scan`, `nikto_scan`, `hydra_bruteforce` — exploitation (dangerous=True)
- `generate_report` — reporting
- `shell` — generic shell execution (dangerous=True, logged, gated by `guardrails.py`)
- `http_request` — generic HTTP requests
- `parse_tool_output` — filter/truncate raw nmap/sqlmap/nikto/generic output

See `skills.py` for the methodology guidance (which tools map to which phase
of an engagement) injected into every system prompt via `prompt_builder.py`.

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
