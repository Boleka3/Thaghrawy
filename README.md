# Thaghrawy

An AI-assisted penetration testing harness with persistent, cross-engagement
memory.

> ⚠️ For authorized security testing only. Use only against systems you own
> or have explicit written permission to test.

## Quickstart

```bash
pip install -r requirements.txt
cp .env.example .env        # fill in your LLM provider's API key
python main.py               # starts FastAPI on :8000
```

Open `http://localhost:8000` for the dark hacker-themed UI: pick or create
an engagement on the left, chat with the agent in the middle, and watch
findings collect on the right. The WebSocket at `/ws/chat?engagement_id=...`
streams `memory_hit` / `tool_call` / `tool_result` / `token` /
`finding_saved` / `done` / `error` events.

## Running with Docker

The full stack (agent + DVWA + Juice Shop targets) runs via Docker Compose. The
compute backend for the embedding model is modular — pick the one matching your host:

```bash
# CPU-only (default) — lean image, runs anywhere
docker compose up --build

# NVIDIA GPU — needs the NVIDIA Container Toolkit on the host
docker compose -f docker-compose.yml -f docker-compose.gpu-nvidia.yml up --build

# AMD GPU — needs the ROCm kernel driver on the host
docker compose -f docker-compose.yml -f docker-compose.gpu-amd.yml up --build
```

The CPU build avoids pulling the multi-GB CUDA torch wheels; the GPU overrides select the
matching torch wheel index (`cuda`/`rocm`) via the `COMPUTE_BACKEND` build arg and pass the
GPU devices through to the container. Inside the compose network the agent reaches DVWA at
`http://dvwa:80` and Juice Shop at `http://juice-shop:3000`.

## Architecture

```
main.py                FastAPI app: serves frontend/, mounts api/ routers, /ws/chat
core/
  agent.py             Tool-calling ReAct loop (PentestAgent)
  llm.py                Anthropic / OpenAI / Ollama, normalized streaming events
  tools.py              Unified tool registry (recon/exploit/report/memory/shell/http)
  context.py            Context window trimming + tool-output truncation
memory/
  store.py              ChromaDB interface (findings + techniques collections)
  embeddings.py         local sentence-transformers wrapper
  schemas.py             Finding / Technique / Engagement pydantic models
engagements/
  manager.py             engagement CRUD, JSON + markdown session logs
  sessions/               per-engagement data (gitignored)
mcp_servers/
  recon_server.py         consolidated recon tools (see "MCP consolidation" below)
  exploit_server.py        sqlmap / nikto / hydra
  report_server.py         markdown + PDF report generation
  tools/                   per-tool wrapper modules used by recon_server.py
api/
  routes/                 chat, engagements, findings, memory REST endpoints
  websocket.py             streaming chat
frontend/                 dark hacker-themed single page UI
guardrails.py             JSON enforcement + dangerous-shell-command gating/logging
output_filter.py          per-tool output truncation/extraction
prompt_builder.py         system prompt construction, memory + methodology injection
skills.py                 methodology guidance per engagement phase (recon/exploit/etc.)
reports/                  example real pentest reports from earlier engagements
```

## MCP tool servers

`mcp_servers/recon_server.py` registers ~30 recon/scanning tools (subdomain enum,
port scanning, HTTP probing, fuzzing, crawling, vuln templates, TLS/WAF checks,
parameter discovery, SMB enumeration, exploit-DB lookup, whois, etc.) as MCP tools,
backed by testable wrapper functions in `mcp_servers/tools/`. `mcp_servers/exploit_server.py`
holds the three tools that actively attack a target (sqlmap, nikto, hydra) and are
registered with `dangerous=True`. Every scan tool goes through
`mcp_servers/tools/_common.py::run_command()`, which enforces a real subprocess
timeout so a hung scan can't block the agent forever.

`skills.py` maps each phase of a pentest (recon, content discovery, vuln scanning,
exploitation, network/AD, reporting) to the tools relevant to it and OWASP/PTES-style
guidance text. `prompt_builder.py` injects this as a methodology reference into every
system prompt — it's guidance for the LLM's tool-calling loop, not a rigid phase gate.

Note the directory is `mcp_servers/`, not `mcp/` — naming it `mcp/` would shadow the
installed `mcp` SDK package that these servers themselves import
(`from mcp.server.fastmcp import FastMCP`).

## Multi-LLM support

Set `LLM_PROVIDER` in `.env` to `anthropic`, `openai`, or `ollama`. `OpenAIProvider`
also accepts `OPENAI_BASE_URL` for any OpenAI-compatible endpoint (e.g. LM Studio).

## Branch map

See [CLAUDE.md](./CLAUDE.md) for the full branch-ownership table and contribution rules.

## Security notes

- The `shell` and exploitation tools (`sqlmap_scan`, `nikto_scan`, `hydra_bruteforce`)
  are intentionally dangerous by design — gate usage with engagement scope and
  `DANGEROUS_COMMANDS_REQUIRE_CONFIRM`.
- Every shell command is logged to `engagements/sessions/shell_command_log.jsonl`.
- `.env` is gitignored and CI fails the build if one is ever committed.
