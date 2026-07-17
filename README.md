<div align="center">

# 🛡️ Thaghrawy

### An open-source, AI-powered autonomous penetration-testing assistant

*A ReAct agent that drives 34 real security tools over the Model Context Protocol (MCP), keeps a human in the loop, remembers findings across engagements, and writes the report for you.*

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-async-009688?logo=fastapi&logoColor=white)
![MCP](https://img.shields.io/badge/Protocol-MCP-6E56CF)
![ChromaDB](https://img.shields.io/badge/Memory-ChromaDB-FF6F61)
![Docker](https://img.shields.io/badge/Deploy-Docker%20Compose-2496ED?logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/tests-582%20passing-2ea44f)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

> ⚠️ **For authorized security testing only.** Use Thaghrawy exclusively against systems you own or have explicit written permission to test. You are responsible for staying within your legal and contractual scope.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [The Tools — Three MCP Servers](#the-tools--three-mcp-servers)
- [Quickstart (Docker)](#quickstart-docker)
- [Practice Targets](#practice-targets)
- [Configuration](#configuration)
- [Using the Agent](#using-the-agent)
- [Reporting](#reporting)
- [Memory](#memory)
- [Safety & Guardrails](#safety--guardrails)
- [Testing & Evaluation](#testing--evaluation)
- [REST & WebSocket API](#rest--websocket-api)
- [Project Structure](#project-structure)
- [Local Development](#local-development)
- [Tech Stack](#tech-stack)
- [Roadmap](#roadmap)
- [Team & Acknowledgements](#team--acknowledgements)
- [License](#license)

---

## Overview

Penetration testing is one of the most effective ways to find and fix security holes before attackers do — but it is slow, expensive, and depends on scarce expert talent. Existing AI security tools are either **passive advisors** (they guide a human who still runs every tool by hand) or **closed-source autonomous platforms** (effective, but inaccessible to the research and education community).

**Thaghrawy** closes that gap. It wraps professional security tools as **MCP servers** so any compatible Large Language Model can call them through one standard interface. A **ReAct-style agent** reconnoitres a target, interprets raw tool output into structured findings, and stores them in a **ChromaDB semantic memory** for cross-engagement recall. Engagements run in phases: the agent enumerates autonomously, then hands off to a **human-in-the-loop** mode where every tool call can be approved, edited, or rejected. Finally it generates **two reports** — a technical one (CVSS, reproduction steps) and an executive one (DREAD, business impact).

Because every human decision is captured, each engagement can be **exported as fine-tuning data** (supervised examples + preference pairs), turning day-to-day use into training data for a stronger agent.

## Key Features

- 🤖 **Autonomous agent, human veto** — a ReAct loop (reason → act → observe) selects and runs tools on its own, but a human approves/edits/rejects every risky action.
- 🔌 **34 real security tools over MCP** — nmap, nuclei, sqlmap, ffuf, dalfox, wapiti, hydra, and more, behind one uniform, model-agnostic interface. New tools plug in without touching the agent core.
- 🧠 **Cross-engagement memory** — confirmed findings and techniques are embedded in ChromaDB and recalled semantically before the agent acts, so lessons carry over.
- 🧩 **Multi-provider LLM** — works with **Anthropic**, **OpenAI** (and any OpenAI-compatible endpoint like LM Studio / OpenRouter), or **Ollama**. Runs fully offline with a local model for zero cost and privacy.
- 🛡️ **Layered safety** — destructive-command guardrails, recon-only mode that physically excludes exploit tools, a runtime human-approval gate, and full shell-command logging.
- 📄 **Dual reporting** — technical (CVSS + reproduction) and executive (DREAD + business impact) reports, rendered Markdown → HTML → PDF.
- 🔁 **Training-data export** — human approve/reject/edit decisions become SFT examples and DPO preference pairs.
- 📊 **Benchmark harness** — measures Exploit Success Rate, Average Steps per Task, false-positive rate, and OWASP Top 10 detection rate against known-vulnerable targets.
- ✅ **582 automated tests** and a Docker-first, reproducible deployment.

## How It Works

**The agent loop (ReAct).** Each turn, the agent reasons about the target, calls a tool through MCP, reads the result, and decides the next step — repeating until the goal is met or an iteration cap is reached. Findings, phase changes, and human decisions are streamed as structured events.

**The engagement lifecycle — three phases:**

| Phase | What happens |
|---|---|
| **1 · Autonomous enumeration** | The agent recons the target on its own and deterministically auto-ingests low-risk findings, then emits a hand-off. |
| **2 · Human-in-the-loop collaboration** | Every proposed tool call is gated — a human **approves**, **edits**, **rejects**, or **stops**. The analyst can also run tools manually and curate findings. |
| **3 · Reporting** | The system generates the technical (CVSS) and executive (DREAD) reports. |

> **Live example (OWASP Juice Shop):** a single `/enumerate` ran the agent's recon tools, produced **21 findings** (e.g. missing security headers), and automatically handed off to the collaboration phase — with zero manual tool-running.

## Architecture

Thaghrawy is a modular, layered system: a dark web UI talks to a FastAPI backend over REST + a streaming WebSocket; the backend hosts a per-engagement agent wired to a tool registry, a memory store, an LLM provider, and a human-in-the-loop control channel; tools are grouped into three MCP servers.

```mermaid
flowchart TD
    UI["Web UI<br/>(Engagements · Agent Chat · Findings)"]
    API["FastAPI Backend<br/>REST + streaming WebSocket"]
    AGENT["PentestAgent<br/>ReAct loop"]
    REG["ToolRegistry<br/>(mode-gated)"]
    MEM["MemoryStore<br/>ChromaDB"]
    LLM["LLMProvider<br/>Anthropic · OpenAI · Ollama"]
    CTRL["AgentControl<br/>human-in-the-loop"]
    RECON["Recon MCP server"]
    EXPLOIT["Exploit MCP server<br/>(gated)"]
    REPORT["Report server"]

    UI <--> API
    API --> AGENT
    AGENT --- REG
    AGENT --- MEM
    AGENT --- LLM
    AGENT --- CTRL
    REG --> RECON
    REG --> EXPLOIT
    REG --> REPORT
The Tools — Three MCP Servers
Every tool is grouped into one of three MCP servers. Each wrapper runs through a common helper (mcp_servers/tools/_common.py) that adds a real subprocess timeout, workspace persistence, a structured JSON result, and command logging — and never builds a shell string.

Server	Role	Examples
Recon server (recon_server.py)	Discovery & scanning — safe, non-destructive. Always registered.	subfinder, amass, assetfinder, dnsx, httpx, naabu, masscan, nmap, katana, gobuster, ffuf, nuclei, wpscan, testssl, wafw00f, whois, arjun, enum4linux, searchsploit, + header/JWT/CSRF/SSRF/XXE checks
Exploit server (exploit_server.py)	Active exploitation — potentially dangerous. Excluded entirely in recon-only mode.	sqlmap, dalfox, wapiti, nikto, hydra, netexec, credential_search, linux_privesc_check
Report server (report_server.py)	Turns findings into deliverables.	generate_report → Markdown → HTML → PDF
The directory is mcp_servers/, not mcp/, so it doesn't shadow the installed mcp SDK package the servers import.

Quickstart (Docker)
Docker Compose is the primary, supported way to run Thaghrawy. It builds an image with all security tools pre-installed — no manual tool setup.

git clone https://github.com/Boleka3/Thaghrawy.git
cd thaghrawy

cp .env.example .env          # add your LLM provider's endpoint / API key
docker compose up --build     # builds the image and starts the agent
Then open http://localhost:8000 — create an engagement on the left, chat with the agent in the middle, and watch findings collect on the right.

Practice Targets
DVWA and OWASP Juice Shop are not started by default. They live behind a targets Compose profile, for exercising the agent against known-vulnerable apps you own:

docker compose --profile targets up --build   # agent + DVWA + Juice Shop
With the profile up, the agent reaches DVWA at http://dvwa:80 and Juice Shop at http://juice-shop:3000 on the compose network. Set TARGET per engagement or in .env.

Configuration
All configuration is driven by .env (copied from .env.example).

LLM provider
Set LLM_PROVIDER to anthropic, openai, or ollama:

Provider	Key settings
Anthropic	ANTHROPIC_API_KEY, ANTHROPIC_MODEL
OpenAI / compatible	OPENAI_API_KEY, OPENAI_MODEL, OPENAI_BASE_URL (point at LM Studio, OpenRouter, llama.cpp, …)
Ollama	OLLAMA_BASE_URL, OLLAMA_MODEL
For a local LLM on the same machine as Docker, use http://host.docker.internal:<port>/v1 and bind the LLM server to 0.0.0.0, not 127.0.0.1.

Other useful knobs: LLM_TEMPERATURE, LLM_MAX_TOKENS, MAX_TOOL_ITERATIONS (agent round-trips per turn), CHROMA_PERSIST_DIR.

Compute backend (CPU / NVIDIA / AMD)
GPU only accelerates the local embedding model (memory), not the LLM — most users should stay on the default CPU build.

Backend	Command
CPU (default)	docker compose up --build
NVIDIA	docker compose -f docker-compose.yml -f docker-compose.gpu-nvidia.yml up --build
AMD (ROCm)	docker compose -f docker-compose.yml -f docker-compose.gpu-amd.yml up --build
The backend is fixed at build time via the COMPUTE_BACKEND build arg — re-run with --build after switching.

Using the Agent
The frontend is a dark, three-panel single page:

Engagements — create/select an engagement (name, target, scope, mode).
Agent Chat — streamed reasoning, tool calls with inline Approve / Reject / Edit controls, a phase banner, and Enumerate / Stop / Run-tool / Report / Help actions.
Findings — a live list with edit and "mark false-positive" actions, plus report links.
Engagement modes:

recon_only — the exploit server is never registered, so the LLM physically cannot run an exploitation tool.
full — recon + exploitation, with the human-approval gate active.
Reporting
One engagement produces two reports from the same findings store:

Report	Audience	Contents
Technical	Engineers & analysts	CVSS score per finding, step-by-step reproduction, evidence & remediation, sorted by severity
Executive	Managers & risk owners	DREAD risk rating, business-impact framing, prioritised and non-technical
Both render Markdown → HTML → PDF via the report server.

Memory
The defining query is "have I seen a finding like this before?" — semantic similarity, not a table lookup. Thaghrawy uses ChromaDB with a local sentence-transformers model (all-MiniLM-L6-v2):

Two collections — findings and techniques — each document embedded with metadata mirroring the Pydantic models.
The agent recalls semantically similar past results before choosing its next move.
Stored as a persistent Docker volume, so memory survives restarts and carries across engagements.
Safety & Guardrails
Security is layered:

Guardrails (guardrails.py) block destructive shell patterns before execution.
Mode-gating — a recon_only engagement never registers the exploit server.
Human-approval gate — dangerous tool calls require an explicit human verdict at runtime (DANGEROUS_COMMANDS_REQUIRE_CONFIRM).
Least privilege & no raw-credential storage.
MCP-risk awareness — tool-poisoning and prompt-injection risks are contained by keeping the human in the loop.
Every shell command is logged to engagements/sessions/shell_command_log.jsonl. .env is gitignored and CI fails the build if one is ever committed.

Testing & Evaluation
Validation runs at three levels, 582 automated tests in total (pytest):

Unit — pure logic with the real tools mocked (argv building, output parsing, the control channel, finding-draft mapping, the exporter).
Integration — the FastAPI app + WebSocket driven end-to-end over a real ASGI stack.
Live smoke — every registered tool run against an owned target, to catch real-CLI bugs that mocks can't.
pytest                 # run the full suite
Benchmarks. The harness (benchmarks/) runs the agent against a target, then scores the saved findings against that target's known vulnerability categories (ground_truth.py, mapped to OWASP Top 10):

ESR (Exploit Success Rate) = matched categories ÷ known categories
AST (Average Steps per Task) = total steps ÷ turns
FP-rate = unmatched findings ÷ total findings
Detection rate = distinct OWASP Top 10 classes detected
python -m benchmarks.runner <engagement_id> <target>   # e.g. ... dvwa
Metric attainment is model-bound: a weak local model recons well but is poor at multi-step exploitation. The pipeline itself is validated end-to-end; a stronger model moves the numbers toward target.

REST & WebSocket API
The FastAPI backend exposes REST routers under api/routes/ (chat, engagements, findings, memory, reports, tools, training, lm_studio) and a streaming chat socket at:

/ws/chat?engagement_id=...
which streams memory_hit / tool_call / tool_result / token / finding_saved / done / error events, plus phase changes and approval prompts.

Project Structure
main.py                FastAPI app: serves frontend/, mounts api/ routers, /ws/chat
core/
  agent.py             Tool-calling ReAct loop (PentestAgent)
  llm.py               Anthropic / OpenAI / Ollama, normalized streaming events
  tools.py             Unified tool registry (recon/exploit/report/memory/shell/http)
  control.py           Human-in-the-loop control channel (approve/reject/edit/stop)
  context.py           Context-window trimming + tool-output truncation
  finding_drafts.py    Maps scanner output to structured Findings (auto-ingest)
memory/
  store.py             ChromaDB interface (findings + techniques collections)
  embeddings.py        Local sentence-transformers wrapper
  schemas.py           Finding / Technique / Engagement Pydantic models
engagements/manager.py  Engagement CRUD, JSON + trajectory session logs
mcp_servers/
  recon_server.py      Recon & discovery tools
  exploit_server.py    Active exploitation tools (dangerous, gated)
  report_server.py     Markdown + PDF report generation
  tools/               Per-tool, framework-free wrapper modules
reporting/builder.py   Pure functions that build the technical + executive reports
training/exporter.py   SFT examples + DPO preference pairs
benchmarks/            Ground truth, scorer, runner for the four metrics
api/                   REST routers + websocket.py
frontend/              Dark three-panel single-page UI
guardrails.py          Dangerous-shell-command gating + logging
prompt_builder.py      System prompt construction, memory + methodology injection
skills.py              Methodology guidance per engagement phase
tests/                 582 automated tests
Local Development
Running on the host is supported for development and the test suite, but you must install the security tools yourself — Docker is what guarantees they're all present.

pip install torch --index-url https://download.pytorch.org/whl/cpu   # skip the multi-GB CUDA build
pip install -r requirements.txt
cp .env.example .env
python main.py              # FastAPI on :8000
See CONTRIBUTING.md for the architecture overview and contribution rules.

Tech Stack
Layer	Technology
Backend / API	Python 3, FastAPI, WebSocket
Agent	Custom ReAct loop
Tool protocol	Model Context Protocol (MCP SDK / FastMCP)
Memory	ChromaDB + sentence-transformers (all-MiniLM-L6-v2)
LLM	Anthropic · OpenAI-compatible · Ollama
Reporting	Markdown → HTML → PDF (xhtml2pdf)
Security tools	nmap, nuclei, sqlmap, dalfox, wapiti, hydra, …
Packaging	Docker, Docker Compose
Testing	pytest (582 tests)
Roadmap
Drive the pipeline with a stronger hosted model and re-measure the benchmarks.
Automate authenticated (logged-in) scanning to reach deeper attack surface.
Add dedicated IDOR / SSRF coverage and expand the OWASP surface.
Fine-tune and evaluate an improved model on the exported preference data.
Team & Acknowledgements
Graduation project — Faculty of Computers and Artificial Intelligence.

Team: Loay Ahmed Badea · Youssef Ali Mohamed · Yehia Mohamed Othman · Mohamed Abd El-Nasser · Omar Ayman Mesbah · Belal Mohamed Youness.

Built on the open-source work of the MCP, ReAct, ChromaDB, and OWASP communities, and the many security tools Thaghrawy orchestrates.

Thaghrawy · Autonomous Pentesting Agent · Use responsibly, only within authorized scope.

</div>
