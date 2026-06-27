# Thaghrawy: An AI-Powered Autonomous Penetration Testing Assistant

## Phase 1 Short Documentation (Appendix B.3)

**Cairo University | Faculty of Computers and Artificial Intelligence**
**Department of Information Technology | Academic Year 2025–2026**

---

| Field | Value |
|---|---|
| **Project Title** | Thaghrawy: An AI-Powered Autonomous Penetration Testing Assistant |
| **Document Type** | Phase 1 Short Documentation |
| **Supervisor** | Prof. Haitham S. Hamza |
| **Team Members** | Loay Ahmed Badea, Youssef Ali Mohamed, Yehia Mohamed Othman, Mohamed Abd El-Nasser, Omar Ayman Mesbah, Belal Mohamed Youness |

---

## Abstract

Thaghrawy is an AI-powered autonomous penetration testing assistant that combines a Large
Language Model (LLM) agent with 30 professional security tools (nmap, sqlmap, nuclei, and
others) to automate the reconnaissance and vulnerability assessment phases of an engagement.
The system maintains persistent semantic memory across engagements using a ChromaDB vector
store, enabling it to recall relevant past findings automatically. A human-in-the-loop safety
layer (shell guardrails and FR-01 recon-only mode) prevents genuinely dangerous operations
without restricting standard security tool invocations. Dual-audience PDF reports — one
technical and one executive — are generated from confirmed findings, with DREAD risk scores
for prioritisation. The project targets DVWA and Juice Shop as benchmark platforms and
measures performance using Engagement Success Rate (ESR), Attack Success Rate (AST), and
false-positive rate. A 349-test CI-enforced pytest suite validates every module.

---

## Chapter 1: Introduction

### 1.1 Background and Motivation

The global cybersecurity skills gap is widening: millions of security positions go unfilled
annually while attack sophistication continues to increase. Penetration testing — the
practice of proactively finding and demonstrating exploitable vulnerabilities before attackers
do — is one of the most effective defences, yet it remains expensive, time-consuming, and
reliant on individual expertise. A junior analyst may take several days to conduct an
assessment that an experienced tester completes in hours.

Recent advances in Large Language Models (LLMs) have demonstrated that AI systems can reason
about multi-step technical tasks, interpret CLI tool output, and autonomously select and
sequence tools toward a goal. Applying this capability to penetration testing could
significantly reduce assessment time, lower the expertise threshold, and enable consistent
methodology compliance across security teams of varying seniority.

### 1.2 Problem Definition

Current AI-assisted security tools fall into two categories:

1. **Passive advisors** (e.g., PentestGPT, 2023): an LLM that guides a human analyst through a
   methodology, but the human still runs every tool manually. The AI cannot act on its own.

2. **Script-based automation** (e.g., Metasploit, automated scanners): tools that follow rigid
   predefined scripts and cannot adapt their strategy based on intermediate findings.

Neither category provides an agent that: (a) autonomously decides which tool to invoke based
on live context, (b) interprets unstructured CLI output and extracts structured findings,
(c) recalls relevant knowledge from past engagements, and (d) maintains human-in-the-loop
safety without restricting the full assessment workflow.

Thaghrawy addresses all four requirements.

### 1.3 Project Objectives and Proposed Solution

**Primary objectives:**

1. Build an LLM-agent loop that autonomously orchestrates 30+ real security CLI tools across
   the full penetration testing methodology (recon, scanning, exploitation, reporting)
2. Implement persistent semantic memory that enables cross-engagement knowledge recall
3. Produce dual-audience PDF reports (technical and executive) from structured findings
4. Enforce safety through registry-level exploit gating (FR-01) and shell pattern guardrails
5. Measure accuracy using ESR/AST/FP-rate benchmarks against DVWA and Juice Shop

**Success metrics (from project proposal):**

- Engagement Success Rate (ESR) >= 80% on DVWA vulnerability categories
- False-positive rate <= 15%
- Time-to-first-finding reduced by >= 60% vs manual workflow

**Solution summary:**

The system uses a ReAct (Reason-Act-Observe) agent loop. On each iteration the LLM:
(1) reasons about the current context and past tool results,
(2) selects a tool from the registered tool registry,
(3) receives and parses the tool's output, and
(4) decides whether to continue, save a finding, or produce a final answer.

All confirmed findings are persisted to ChromaDB via `save_finding`, making them
retrievable in future engagements through semantic similarity search.

### 1.4 Scope and Limitations

**In scope:**

- Web application penetration testing (OWASP Top 10 categories)
- Network reconnaissance against lab and authorised targets
- Automated report generation from confirmed findings
- Benchmark evaluation on DVWA and Juice Shop Docker instances

**Out of scope:**

- Physical security testing
- Social engineering or phishing simulation
- Production-environment testing without explicit written authorisation
- Exploit development (the system uses existing public tools, not custom exploits)

**Known limitations:**

- LLM token cost: each engagement consumes API tokens; cost scales with target complexity
- Tool availability: all 30 CLI tools must be installed on the host system
- Benchmark run pending: the harness is implemented; live DVWA numbers will be produced
  before the Phase 2 (final) submission

---

## Chapter 2: Related Work

### 2.1 Ars0n-Framework [1]

Ars0n-Framework is an open-source automated bug-bounty scanning framework written in Go.
It inspired Thaghrawy's multi-tool integration concept. The key difference is that
Ars0n-Framework runs tools in a fixed pipeline; Thaghrawy's LLM agent selects tools
dynamically based on intermediate results.

### 2.2 PentestGPT [2]

PentestGPT (He et al., NTU Singapore, 2023) uses GPT-4 to guide a human analyst through a
penetration testing methodology. The human still executes every tool manually; PentestGPT
provides decision support, not autonomy. Thaghrawy is fully autonomous at the tool-call
level: the agent invokes, parses, and saves findings without per-call human intervention.

### 2.3 AutoGPT and Autonomous Agents [3]

AutoGPT demonstrated that LLMs can act as autonomous agents that iteratively plan and execute
steps toward a goal. Thaghrawy adapts this pattern to the constrained cybersecurity domain,
replacing open-ended tool creation with a fixed registry of vetted security tools — providing
stronger safety guarantees than a general-purpose agent.

### 2.4 ChromaDB for Agent Memory [4]

ChromaDB is a vector database designed for AI applications. Its use as a persistent agent
memory store — enabling cross-session semantic recall — distinguishes Thaghrawy from
engagement-stateless security tools that start from scratch on every run.

### 2.5 DREAD Risk Model [5]

DREAD (Damage, Reproducibility, Exploitability, Affected users, Discoverability) is a
qualitative risk scoring model used in security assessments. Thaghrawy implements DREAD as
an agent-estimated numerical score per confirmed finding, used to prioritise findings within
the same CVSS severity band in the executive report.

---

## Chapter 3: System Analysis

### 3.1 Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| FR-01 | The system shall support recon-only and full-analysis engagement modes | High |
| FR-02 | The agent shall autonomously select and invoke tools from a registered tool library | High |
| FR-03 | The system shall persist findings and techniques to a semantic memory store | High |
| FR-04 | The system shall generate technical and executive PDF reports from saved findings | High |
| FR-05 | The system shall support multiple LLM providers (Anthropic, OpenAI, Ollama) | Medium |
| FR-06 | The system shall provide a REST API and WebSocket interface for all operations | Medium |
| FR-07 | The system shall measure engagement accuracy using ESR, AST, and FP-rate | Medium |
| FR-08 | The system shall block dangerous shell commands via a configurable guardrails layer | High |
| FR-09 | The system shall support DREAD risk scoring on each confirmed finding | Medium |
| FR-10 | The system shall stream agent reasoning and tool results in real time | Low |

### 3.2 Use Case Diagram (Text)

**Primary Actors:** Security Analyst, AI Agent (internal), LLM Provider (external)

**Key Use Cases:**

- **UC-01 — Start engagement:** Analyst creates engagement (name, target, scope, mode).
  System initialises agent registry for that mode and creates ChromaDB collections.
- **UC-02 — Run reconnaissance:** Analyst sends a natural-language prompt.
  Agent invokes recon tools, parses output, saves techniques, reports findings via WebSocket.
- **UC-03 — Recall past findings:** Agent queries semantic memory before each tool call;
  matching past findings are injected into context (memory_hit event).
- **UC-04 — Save a finding:** Agent calls save_finding with structured data;
  finding is embedded and stored; frontend is notified via WebSocket event.
- **UC-05 — Generate reports:** Analyst triggers generate_report; system builds
  technical + executive markdown and renders both as PDF.
- **UC-06 — View and download reports:** Analyst opens reports list; clicks PDF link.

---

## Chapter 4: Initial Design

### 4.1 System Architecture

```
+------------------+      HTTP/WS      +-------------------+
|  Web Frontend    |<----------------->|   FastAPI Server   |
|  frontend/       |                   |   main.py, api/    |
+------------------+                   +---------+---------+
                                                  |
                                   +--------------v--------------+
                                   |      PentestAgent           |
                                   |      core/agent.py          |
                                   |   [ReAct loop, streaming]   |
                                   +-+----------+----------+-----+
                                     |          |          |
                          +----------v--+  +----v-----+  +-v----------+
                          | ToolRegistry|  |MemoryStore|  |LLMProvider|
                          | core/tools  |  |ChromaDB   |  |core/llm   |
                          +------+------+  +----------+  +-----------+
                                 |
              +------------------+------------------+
              |                  |                  |
       +------v------+   +-------v------+   +-------v------+
       | recon_server|   |exploit_server|   |report_server |
       | (15 tools)  |   |(sqlmap, nikto|   |(md -> PDF)   |
       |             |   | hydra)       |   |              |
       +-------------+   +--------------+   +--------------+
```

### 4.2 Agent ReAct Loop Sequence

```
Analyst      WebSocket     PentestAgent    ToolRegistry    ChromaDB
  |              |               |              |              |
  |-[user msg]-->|               |              |              |
  |              |---[prompt]--->|              |              |
  |              |               |--[search_memory]-->|       |
  |              |               |              |--[query]---->|
  |              |               |<--[results]--|<--[hits]----|
  |              |<--[memory_hit]|              |              |
  |              |               |--[LLM: reason + pick tool] |
  |              |<--[tool_call]-|              |              |
  |              |               |--[execute(tool, args)]-->| |
  |              |               |<--[tool output]----------|  |
  |              |<--[tool_result|              |              |
  |              |               |--[LLM: save finding?]      |
  |              |               |--[save_finding]-->|        |
  |              |               |              |--[upsert]-->|
  |              |<-[finding_saved]             |              |
  |              |               | [repeat <= MAX_ITERATIONS] |
  |              |<--[done]------|              |              |
```

---

## Work Plan Status Table

| # | Task | Status | Target |
|---|---|---|---|
| 1 | Requirements + architecture design | Completed | Week 2, Sem 1 |
| 2 | LLM provider abstraction (Anthropic/OpenAI/Ollama) | Completed | Week 4, Sem 1 |
| 3 | Tool registry + first 5 recon wrappers | Completed | Week 5, Sem 1 |
| 4 | ChromaDB memory store + embeddings | Completed | Week 6, Sem 1 |
| 5 | Engagement lifecycle + persistence | Completed | Week 7, Sem 1 |
| 6 | FastAPI REST + WebSocket + frontend | Completed | Week 9, Sem 1 |
| 7 | Expand to 30 tools | Completed | Week 11, Sem 1 |
| 8 | DREAD scoring + FR-01 recon-only toggle | Completed | Week 13, Sem 1 |
| 9 | Dual PDF report generation | Completed | Week 14, Sem 1 |
| 10 | 349-test CI suite (pytest + flake8) | Completed | Week 14, Sem 1 |
| 11 | DVWA live benchmark run (ESR/AST/FP-rate) | In Progress | Week 4, Sem 2 |
| 12 | Final documentation (50-70 pp.) + A0 poster | Planned | Week 13, Sem 2 |

---

## References

[1] Ars0n-Framework. Open-source automated bug-bounty scanning framework.
Available: https://github.com/R-s0n/ars0n-framework

[2] J. He, M. Balwierz, M. Gerber, and J. Liu, "PentestGPT: An LLM-Empowered
Automatic Penetration Testing Tool," arXiv preprint arXiv:2308.06782, 2023.

[3] T. Significant Gravitas, "AutoGPT: An Autonomous GPT-4 Experiment," GitHub, 2023.
Available: https://github.com/Significant-Gravitas/AutoGPT

[4] Chroma, "ChromaDB: The AI-native Open-Source Embedding Database," GitHub, 2023.
Available: https://github.com/chroma-core/chroma

[5] Microsoft Corporation, "DREAD Threat Risk Rating System," Microsoft Security
Engineering, 2002. Available: https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648644(v=pandp.10)
