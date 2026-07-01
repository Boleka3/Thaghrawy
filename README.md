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

### Connectivity & LLM endpoints

Connectivity is fully config-driven — the container reaches whatever you point it at
through `.env`, so any deployer can bring their own LLM and targets.

**External targets & cloud LLM APIs work with no extra setup.** The container has outbound
internet egress via the default bridge network, so cloud LLM APIs (Anthropic/OpenAI/…) and
external scan targets (e.g. a HackerOne scope) are reachable out of the box. Raw-socket
scans (`nmap -sS`, `masscan`) work because the container runs as root with the default
`NET_RAW` capability; on a hardened host that strips it, uncomment `cap_add: [NET_RAW,
NET_ADMIN]` in `docker-compose.yml`.

**LLM endpoint** — set `OPENAI_BASE_URL` in `.env` to match where your LLM lives:

| Where the LLM runs | `OPENAI_BASE_URL` |
|---|---|
| Cloud API (OpenAI) | *(leave empty)* |
| Cloud-compatible (OpenRouter, …) | `https://openrouter.ai/api/v1` |
| Local, on **this** Docker host (LM Studio/Ollama) | `http://host.docker.internal:1234/v1` |
| Local, on **another LAN** machine | `http://<lan-ip>:1234/v1` |
| A sibling compose service | `http://<service-name>:<port>/v1` |

The base compose maps `host.docker.internal` to the Docker host (requires Docker Engine
≥ 20.10), so a local LLM on the same machine is reachable regardless of that host's IP —
just **bind the LLM server to `0.0.0.0`, not `127.0.0.1`**. For Ollama use the same host with
`OLLAMA_BASE_URL=http://host.docker.internal:11434`. Verify from inside the container:

```bash
docker compose exec agent sh -c 'curl -s https://example.com -o /dev/null -w "egress %{http_code}\n"'
docker compose exec agent sh -c 'curl -s http://host.docker.internal:1234/v1/models'
curl http://localhost:8000/api/lm-studio/status   # 200 + "loaded": true when the LLM is reachable
```

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

Wrapper conventions worth knowing:

- **Host scanners take a host, not a URL.** `nmap_scan`, `masscan_scan`, and
  `naabu_scan` normalize their target through `_common.py::strip_url()`, so
  `http://host/path` is accepted and reduced to `host` (nmap otherwise fails with
  "Unable to split netmask" and reports zero ports).
- **HTTP probing uses the ProjectDiscovery binary.** `httpx_scan` invokes
  `httpx-toolkit` (its Kali/Docker name) so the Python `httpx` HTTP-client CLI in
  the venv can't shadow it; it falls back to `httpx` for bare-metal installs.
- **Port presets vs. explicit ports.** `naabu_scan`'s `top_ports` is naabu's
  preset and only accepts `full`/`100`/`1000`; pass an explicit list/range
  (`80,443,8080`, `1-1000`) via `ports`. A comma list mistakenly sent as
  `top_ports` is still routed to `-p` rather than erroring. `masscan_scan`
  accepts `top_ports` only as an alias for `ports`.
- **amass in Docker** is symlinked to the upstream binary (`/usr/lib/amass/amass`)
  to bypass Kali's wrapper script, which otherwise runs `sudo libpostal_data` and
  fails inside the container. On bare-metal Kali the same wrapper needs libpostal
  data (or an upstream `amass` earlier on `PATH`).

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
