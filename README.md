# RedTeam AI

An AI-assisted penetration testing harness with persistent, cross-engagement
memory. Built as a graduation project on top of three earlier prototypes
(`ai_pentest_agent`, `webpentest-mcp-server`, and this repo's own
`mcp-recon-server`), now consolidated into one codebase.

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
prompt_builder.py         system prompt construction, memory injection
skills.py                 legacy phase/skill metadata (recon/vuln_scan/exploit/report)
reports/                  example real pentest reports from earlier engagements
```

## MCP consolidation

This project's history had three separate recon implementations:
`ai_pentest_agent/mcp_servers/recon_server.py`, `webpentest-mcp-server/recon_server.py`,
and this repo's own `mcp-recon-server/`. `mcp_servers/recon_server.py` here is the
merge: the JSON-envelope + workspace-persistence pattern and most parsers came from
`webpentest-mcp-server` (it was the most complete of the three), and `amass`/`ffuf`
were ported from this repo's tools (fixing `whois.py`, which had missing imports and
an undefined variable in the original). Every scan tool now goes through
`mcp_servers/tools/_common.py::run_command()`, which adds a real subprocess timeout —
none of the three originals had one, so a hung scan used to block the agent forever.

Note the directory is `mcp_servers/`, not `mcp/` — naming it `mcp/` would shadow the
installed `mcp` SDK package that these servers themselves import
(`from mcp.server.fastmcp import FastMCP`).

## Multi-LLM support

Set `LLM_PROVIDER` in `.env` to `anthropic`, `openai`, or `ollama`. `OpenAIProvider`
also accepts `OPENAI_BASE_URL` for any OpenAI-compatible endpoint (e.g. LM Studio),
covering the local-LLM setup the original prototype used.

## Branch map

See [CLAUDE.md](./CLAUDE.md) for the full branch-ownership table and contribution rules.

## Security notes

- The `shell` and exploitation tools (`sqlmap_scan`, `nikto_scan`, `hydra_bruteforce`)
  are intentionally dangerous by design — gate usage with engagement scope and
  `DANGEROUS_COMMANDS_REQUIRE_CONFIRM`.
- Every shell command is logged to `engagements/sessions/shell_command_log.jsonl`.
- `.env` is gitignored and CI fails the build if one is ever committed.
