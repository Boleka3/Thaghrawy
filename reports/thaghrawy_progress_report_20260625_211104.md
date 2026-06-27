# Thaghrawy — Project Progress Report

**Cairo University | Faculty of Computers and Artificial Intelligence**
**Academic Year 2025–2026 | June 2026**

**Team:** Loay Ahmed Badea · Youssef Ali Mohamed · Yehia Mohamed Othman ·
Mohamed Abd El-Nasser · Omar Ayman Mesbah · Belal Mohamed Youness

**Supervisor:** Prof. Haitham S. Hamza, Department of Information Technology

---

## 1. Project Overview

Thaghrawy is an AI-powered autonomous penetration testing assistant.
It wraps 30 professional security tools (nmap, sqlmap, nuclei, amass, ffuf, gobuster, etc.)
behind a single conversational interface driven by a Large Language Model (LLM) agent.
Security teams interact with the system in natural language; the agent autonomously decides
which tools to invoke, interprets their output, saves findings to a persistent semantic
memory store, and produces dual-audience reports — one detailed technical report for
developers, and one risk-focused executive summary for management.
All tool activity is logged and gated through a safety guardrails layer.

---

## 2. Term 1 Proposal vs Actual Implementation

| Area | Term 1 Proposal | Actual Implementation | Status |
|---|---|---|---|
| Recon engine language | Go (goroutines / worker pools) | Python (subprocess wrappers) | Changed — see §3.1 |
| Primary storage | PostgreSQL | ChromaDB (vector store) + JSON files | Changed — see §3.2 |
| Agent architecture | Planner-Executor-Perceptor (3-agent) | Single ReAct loop (tool-calling) | Simplified |
| LLM host | LM Studio (local-only) | Multi-provider: Anthropic / OpenAI / Ollama | More flexible |
| Vulnerability detection | Custom heuristics (test_sqli(), etc.) | Mature tools: sqlmap, nuclei, nikto | Higher quality |
| XSS analysis | Playwright DOM analysis | nuclei + nikto templates | Changed |
| Tool count | ~5 planned | 30 real CLI wrappers | Exceeded |
| Reporting | Single markdown report | Dual PDF reports (technical + executive) | Exceeded |
| DREAD risk model | Mentioned in requirements | dread_score on Finding + executive report | Implemented |
| FR-01 mode control | Recon-only / full-analysis toggle | analysis_mode on Engagement | Implemented |
| Docker isolation | Per-component containers | docker-compose (agent + DVWA target) | Implemented |
| Benchmark targets | DVWA, Juice Shop | Scoring harness ready; live run pending | Partially done |
| Test suite | Not mentioned | 349 pytest tests, CI-enforceable | Exceeded |
| Human-in-loop safety | Policy-driven auth middleware | guardrails.py shell pattern blocklist | Narrowed |

---

## 3. Architecture Pivots and Rationale

### 3.1 Go → Python

The Term 1 proposal chose Go for the recon engine, citing goroutine-based concurrency
and the Ars0n-Framework as prior art. The actual performance bottleneck in tool
orchestration is the wall-clock time of external CLI tools (an nmap scan, a sqlmap run)
— not orchestration overhead. No Go concurrency primitive changes how fast nmap finishes;
goroutines save milliseconds on top of processes that run for minutes.

Python was chosen because the entire LLM-tooling ecosystem (Anthropic SDK, OpenAI SDK,
ChromaDB client, FastAPI, sentence-transformers) is Python-first.
A single-language codebase is maintainable by a six-student team in one academic semester,
and Python's subprocess module wraps external CLI tools as cleanly as any Go os/exec call.

### 3.2 PostgreSQL → ChromaDB

PostgreSQL was proposed as a general-purpose shared state store.
The dominant access pattern that emerged during design is:
"Have we seen something like this before across all past engagements?"
This is semantic similarity search — not a relational query.
ChromaDB handles this natively via local sentence-transformer embeddings
(all-MiniLM-L6-v2, runs fully offline) without requiring pgvector or schema migrations.

Structured engagement records (which do need simple CRUD) use one JSON file per engagement,
avoiding the overhead of running two storage systems and removing the PostgreSQL
setup dependency from every developer's machine.

### 3.3 Full Autonomous → Human-in-the-Loop (not a new pivot)

The Term 1 proposal already specified human-in-the-loop confirmation for high-risk
actions (Section 4.7), so this is the intended design, not a change.
The actual scope is narrower than the proposal's "policy-driven authorization middleware":
`guardrails.py` blocks dangerous shell patterns (rm -rf, mkfs, dd, /dev/sd* writes,
fork bombs) on the generic `shell` tool, with a `force` flag and a
`DANGEROUS_COMMANDS_REQUIRE_CONFIRM` config variable.
Every specific security tool (nmap, sqlmap, nuclei, etc.) runs without a per-call gate.
The risk of scope violation is addressed by FR-01: a `recon_only` engagement physically
never has exploit tools registered in the agent's tool registry.

---

## 4. Current Feature Inventory

### 4.1 Security Tool Wrappers (30 tools)

**Reconnaissance (15):** nmap, masscan, amass, subfinder, assetfinder, dnsx, httpx, naabu,
katana, gobuster, ffuf, arjun, whois, wafw00f, web_tech_detect

**Vulnerability Scanning (5):** nuclei, nikto, testssl, wpscan, searchsploit

**Exploitation (2):** sqlmap, hydra

**SMB / Active Directory (2):** enum4linux, netexec

**Workspace Utilities (3):** list_workspace, read_file, grep_workspace

**Agent Memory (4):** save_finding, save_technique, search_memory, load_engagement_context

**Reporting (1):** generate_report

### 4.2 Agent and Memory

- **ReAct loop** (core/agent.py): Reason-Act-Observe cycle; MAX_TOOL_ITERATIONS=8;
  streaming events (token / tool_call / tool_result / memory_hit / finding_saved / error / done)
- **Multi-provider LLM** (core/llm.py): Anthropic Claude (default), OpenAI-compatible,
  Ollama local — same BaseLLMProvider interface
- **ChromaDB memory** (memory/store.py): findings and techniques collections;
  local sentence-transformers embeddings (all-MiniLM-L6-v2, offline-capable)
- **Engagement persistence** (engagements/manager.py): one JSON file + one markdown
  session log per engagement; CRUD over FastAPI REST endpoints

### 4.3 Reporting

- `reporting/builder.py`: pure functions `build_technical_report()` + `build_executive_report()`
- `mcp_servers/report_server.py`: markdown to HTML to PDF via xhtml2pdf
- Both reports generated in one call to `generate_report(engagement_id)`
- **DREAD risk score**: 1-10 field on every Finding; executive report sorts by severity
  first, then DREAD descending within the same severity band

### 4.4 Safety and Control

- `guardrails.py`: regex blocklist of dangerous shell patterns;
  `force` override; `DANGEROUS_COMMANDS_REQUIRE_CONFIRM` env var
- **FR-01 mode toggle**: `analysis_mode: "recon_only" | "full_analysis"` on `Engagement`;
  a `recon_only` agent's tool registry never registers sqlmap, nikto, or hydra

### 4.5 Infrastructure

- **FastAPI** (main.py): REST at /api/, WebSocket chat at /ws/chat, static frontend at /
- **Frontend** (frontend/): dark hacker-themed UI; engagement management, chat, findings panel
- **Docker Compose**: agent service + DVWA target for testing
- **CI** (.github/workflows/ci.yml): pytest + flake8 on every push

### 4.6 Test Suite

- **349 tests** across all modules: pure-logic, MCP tool wrappers, ChromaDB/engagement
  persistence, core agent/LLM/tools, and all FastAPI routes including WebSocket
- **Benchmark harness** (benchmarks/scorer.py): score_engagement(findings, "dvwa") computes
  ESR (Engagement Success Rate), AST (Attack Success Rate), FP rate against DVWA/Juice Shop
  ground-truth vulnerability categories

---

## 5. Branch / Repository State

| Branch | Location | Contents |
|---|---|---|
| `main` (local) | 4 commits ahead of GitHub | Full history including recon+agent rewrite |
| `main` (GitHub origin) | Behind local | Last push before this session's work |
| `feat/dread-recon-toggle-benchmarks` | Local + GitHub | DREAD, FR-01, 349 tests, benchmarks |
| `dev` | Does not exist | Planned in team workflow doc but never created |

**Recommended next steps:**

1. Force-push the cleaned `main` to GitHub (local main has rewritten commit messages)
2. Rebase `feat/dread-recon-toggle-benchmarks` onto the new main
3. Create `dev` branch on GitHub from main
4. Open PR: `feat/dread-recon-toggle-benchmarks` to `dev`, then `dev` to `main`

---

## 6. Honest Gap Analysis

| Proposed Feature | Why Not Built | Current Alternative |
|---|---|---|
| Playwright-based XSS DOM analysis | High complexity; browser automation in a CLI agent adds setup overhead | nuclei XSS templates |
| Custom heuristic detection (test_sqli(), etc.) | Mature tools are more reliable | sqlmap + nuclei |
| LM Studio as MCP host | Replaced by direct Python SDK | Anthropic / OpenAI / Ollama abstraction |
| Planner-Executor-Perceptor (3 agents) | Single ReAct loop proved sufficient | ReAct loop with 30 tools |
| DVWA / Juice Shop live benchmark run | Requires dedicated engagement session; harness ready | Run before final presentation |
| Policy-driven auth middleware | Narrowed to shell guardrails + FR-01 registry gating | guardrails.py + FR-01 |

---

## 7. Professor Discussion Talking Points

### 7.1 Strengths to Highlight

1. **30 real tools** — every tool is a genuine security tool, not a simulation.
   The agent makes real autonomous decisions about which to use.
2. **Persistent cross-engagement memory** — ChromaDB semantic search recalls relevant
   past findings automatically. No comparable student project includes this.
3. **Dual-audience reporting** — technical/executive split addresses the real-world gap
   between developer needs (evidence) and management needs (business impact).
   DREAD scoring adds academic rigour.
4. **349-test CI suite** — production-grade test coverage that would gate merges in
   a real security team workflow.
5. **FR-01 mode toggle** — validated in tests; a `recon_only` agent physically cannot
   attempt exploitation regardless of LLM decision.
6. **Benchmark harness** — ESR/AST/FP-rate metrics match the proposal's stated success
   criteria. A live DVWA run before the final discussion gives concrete numbers.

### 7.2 Anticipated Professor Questions

**Q: Why did you switch from Go to Python?**

The performance bottleneck is the external tool's execution time (nmap scan timeout,
sqlmap crawl), not the orchestration language. Go goroutines save milliseconds on top of
processes that run for minutes. Python was chosen for its first-class LLM ecosystem
(Anthropic SDK, ChromaDB, FastAPI); a single-language codebase is more maintainable for
a six-person student team in one semester.

**Q: Why ChromaDB instead of PostgreSQL?**

The dominant query is semantic similarity — "find past findings similar to this new one."
ChromaDB does this natively via vector embeddings. PostgreSQL would need pgvector and
schema migrations to match the same capability. Structured records use JSON files —
sufficient at this scale, no second database to operate.

**Q: How does Thaghrawy compare to PentestGPT?**

PentestGPT (NTU Singapore, 2023) guides a human tester through methodology but the
human still runs every tool manually. Thaghrawy calls the tools autonomously — the
agent decides, invokes, parses output, and saves findings without per-tool human
intervention. The human gate applies only to genuinely dangerous shell patterns
(disk erasure, etc.), not to standard security tools.

**Q: Did you achieve your proposed success metrics?**

The benchmark harness computing ESR/AST/FP-rate is implemented and all 349 tests pass.
We have conducted DVWA engagements with confirmed SQL Injection, directory traversal,
and outdated-software findings. A full automated benchmark run is scheduled before the
final presentation to produce definitive numbers.

**Q: What is the significance of DREAD scoring?**

DREAD (Damage, Reproducibility, Exploitability, Affected users, Discoverability) is the
risk model the proposal specified for the managerial report. We implemented it as an
agent-estimated numerical score per finding, used to tiebreak findings within the same
severity band in the executive report — directly closing a gap between proposal and implementation.

**Q: How does recon-only mode work technically?**

When a `recon_only` engagement is created, `api/deps.py` calls
`build_filtered_registry(mode="recon_only", ...)` which calls
`build_default_registry(include_exploit_tools=False)`.
The exploit tools (sqlmap, nikto, hydra) are never registered. Even if the LLM decides
to call `sqlmap_scan`, the registry returns "Unknown tool" — there is no prompt-level
enforcement that could be bypassed.

---

*Report generated: June 2026 | Repository: github.com/Boleka3/Thaghrawy*
