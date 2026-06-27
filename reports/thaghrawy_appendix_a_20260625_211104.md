# Appendix A — Graduation Project Initial Proposal

**Cairo University | Faculty of Computers and Artificial Intelligence**
**Unified Graduation Project Bylaws — April 2026**

---

## Section 1 — Project Identification

| Field | Value |
|---|---|
| **Project Title** | Thaghrawy: An AI-Powered Autonomous Penetration Testing Assistant |
| **Department(s)** | Department of Information Technology, FCAI, Cairo University |
| **Academic Year** | 2025–2026 |
| **Semester of Registration** | Semester 1 (ongoing through Semester 2) |
| **Project Category** | Application Development + Data Science & AI |

### Team Members

| # | Name | ID | Program | Email |
|---|---|---|---|---|
| 1 | Loay Ahmed Badea | *(student ID)* | Computer Science | loayabelgendy@gmail.com |
| 2 | Youssef Ali Mohamed | *(student ID)* | Computer Science | *(email)* |
| 3 | Yehia Mohamed Othman | *(student ID)* | Computer Science | yahiamohamed2221@gmail.com |
| 4 | Mohamed Abd El-Nasser | *(student ID)* | Computer Science | mohamedabdnassersoliman@gmail.com |
| 5 | Omar Ayman Mesbah | *(student ID)* | Computer Science | *(email)* |
| 6 | Belal Mohamed Youness | *(student ID)* | Computer Science | *(email)* |

### Supervision

| Role | Name | Title | Department | Email |
|---|---|---|---|---|
| **Primary Supervisor** | Prof. Haitham S. Hamza | Professor | Information Technology, FCAI | *(email)* |
| Co-Supervisor | — | — | — | — |
| Teaching Assistant | — | — | — | — |
| External Sponsor | — | — | — | — |

---

## Section 2 — Project Description

### 2.1 Motivation and Problem Statement (100–200 words)

Cybersecurity threats are escalating in frequency and sophistication while the global
shortage of qualified penetration testers continues to widen. Manual penetration testing
is slow, expensive, and highly dependent on individual expertise — a junior analyst may
spend days reproducing what an experienced professional completes in hours. Small and
medium enterprises (SMEs) often cannot afford dedicated red-team engagements, leaving
critical vulnerabilities undiscovered until exploitation occurs.

Thaghrawy addresses this gap by combining a Large Language Model (LLM) agent with a
comprehensive library of real professional security tools. The system autonomously decides
which reconnaissance and exploitation tools to invoke against a given target, interprets
their raw output, maintains persistent cross-engagement memory, and produces clear
dual-audience reports — enabling less experienced analysts to conduct structured assessments
with the guidance of an AI-powered methodology engine.

### 2.2 Proposed Solution / Project Objective (100–200 words)

Thaghrawy is a conversational AI agent that manages the full penetration testing workflow.
The agent is built on a ReAct (Reason-Act-Observe) loop: it reasons about the current
target context, selects the most appropriate tool from a 30-tool registry, invokes it,
parses the output, and decides whether to continue testing or save a finding and move on.

Key components:

- **30-tool recon and exploit layer** wrapping real CLI tools (nmap, sqlmap, nuclei, amass, and 26 others)
- **ChromaDB semantic memory** that recalls relevant findings across all past engagements
- **FR-01 safety toggle**: recon-only mode that physically prevents the agent from registering exploit tools
- **guardrails.py**: blocks dangerous shell patterns (disk erasure, fork bombs, etc.)
- **Dual PDF reporting**: technical report (evidence, CVSS + DREAD scores) and executive summary (business impact, risk ranking)
- **FastAPI REST + WebSocket API** with a dark-themed hacker web frontend

Primary goals: (1) achieve Engagement Success Rate (ESR) ≥ 80% on DVWA benchmark categories;
(2) maintain false-positive rate ≤ 15%; (3) reduce time-to-first-finding by 60% vs manual workflow.

### 2.3 High-Level Block Diagram / System Architecture

```
+----------------------+      HTTP / WebSocket      +-------------------+
|  Web Frontend        |<-------------------------->|  FastAPI Server   |
|  (HTML / CSS / JS)   |                            |  main.py, api/    |
+----------------------+                            +--------+----------+
                                                             |
                                             +---------------v---------------+
                                             |       PentestAgent            |
                                             |       core/agent.py           |
                                             |  [ReAct: Reason-Act-Observe]  |
                                             +---+----------+----------+-----+
                                                 |          |          |
                                     +-----------v--+  +----v-----+  +-v-----------+
                                     | ToolRegistry |  |MemoryStore|  |LLM Provider|
                                     | core/tools   |  |ChromaDB   |  |Anthropic / |
                                     | 30 wrappers  |  |memory/    |  |OpenAI/Ollama|
                                     +------+-------+  +-----------+  +------------+
                                            |
                   +------------------------+------------------------+
                   |                        |                        |
           +-------v-------+       +--------v------+       +--------v------+
           | recon_server  |       |exploit_server |       |report_server  |
           | 15 recon tools|       |sqlmap, nikto, |       |md -> PDF      |
           |               |       |hydra          |       |(xhtml2pdf)    |
           +---------------+       +---------------+       +---------------+
```

### 2.4 Key Technologies and Tools

| Category | Technologies |
|---|---|
| Language | Python 3.12 |
| Web framework | FastAPI, uvicorn, WebSockets |
| LLM integration | Anthropic Claude API, OpenAI SDK, Ollama |
| Vector memory | ChromaDB, sentence-transformers (all-MiniLM-L6-v2) |
| Data validation | Pydantic v2 |
| Report generation | python-markdown, xhtml2pdf |
| Security tools | nmap, masscan, amass, subfinder, assetfinder, dnsx, httpx, naabu, katana, gobuster, ffuf, arjun, whois, wafw00f, nuclei, nikto, testssl, wpscan, searchsploit, sqlmap, hydra, enum4linux, netexec |
| Containerisation | Docker, Docker Compose |
| Benchmark targets | DVWA (Damn Vulnerable Web Application), Juice Shop |
| Testing | pytest, pytest-anyio, flake8 (349 tests) |
| CI/CD | GitHub Actions |

### 2.5 Stakeholders and Beneficiaries

| Stakeholder | Benefit |
|---|---|
| Security analysts / penetration testers | Automated tool orchestration; consistent methodology; cross-engagement memory recall |
| Development and QA teams | Can run recon-only assessments during SDLC without exploit risk |
| SMEs and startups | Affordable, guided security assessment without a dedicated red team |
| Incident response teams | Fast triage of known vulnerability patterns via semantic memory |
| University cybersecurity researchers | ESR/AST/FP-rate benchmark harness for evaluating AI-driven assessment systems |

### 2.6 Potential Industry Partners (Optional)

Egyptian cybersecurity consultancies, EG-CERT, and cloud-service providers operating in
the MENA region would benefit from a scalable, AI-augmented assessment tool.

---

## Section 3 — Project Plan

| # | Task Title | Description | Responsible | Target Date / Status |
|---|---|---|---|---|
| 1 | Requirements + architecture | Define FR/NFR, select tech stack, design agent loop and memory schema | All | Week 2, Sem 1 — Completed |
| 2 | LLM provider abstraction | Implement BaseLLMProvider, Anthropic + OpenAI + Ollama adapters | Dev 1 | Week 4, Sem 1 — Completed |
| 3 | Tool registry + first 5 wrappers | Build ToolRegistry, nmap, amass, httpx, gobuster, ffuf | Dev 6 | Week 5, Sem 1 — Completed |
| 4 | ChromaDB memory store | MemoryStore: findings + techniques collections, local embeddings | Dev 2 | Week 6, Sem 1 — Completed |
| 5 | Engagement lifecycle | EngagementManager: create/list/close, JSON persistence, session logs | Dev 3 | Week 7, Sem 1 — Completed |
| 6 | FastAPI REST + WebSocket + frontend | /api/ routes, WebSocket chat streaming, dark web UI | Dev 4 + Dev 5 | Week 9, Sem 1 — Completed |
| 7 | Expand tool library to 30 tools | Add masscan, nuclei, nikto, testssl, wpscan, sqlmap, hydra, enum4linux, etc. | Dev 6 | Week 11, Sem 1 — Completed |
| 8 | DREAD scoring + FR-01 toggle | dread_score on Finding; analysis_mode on Engagement; filtered registry | Dev 1 + Dev 2 | Week 13, Sem 1 — Completed |
| 9 | Dual PDF report generation | build_technical_report + build_executive_report; xhtml2pdf pipeline | Dev 1 + Dev 6 | Week 14, Sem 1 — Completed |
| 10 | 349-test CI suite | pytest for all modules, FastAPI routes, WebSocket, benchmarks | All | Week 14, Sem 1 — Completed |
| 11 | DVWA live benchmark run | Full engagement against DVWA Docker instance; measure ESR/AST/FP-rate | All | Week 4, Sem 2 — In Progress |
| 12 | Final documentation + A0 poster | 50-70 page final doc (Appendix B.2); A0 poster | All | Week 13, Sem 2 — Planned |

---

## Section 4 — Declarations and Signatures

We, the undersigned, declare that the information provided in this proposal is accurate
and that we commit to adhering to the Unified Graduation Project Bylaws of the Faculty
of Computers and Artificial Intelligence, Cairo University.

| Student | Signature | Date |
|---|---|---|
| Loay Ahmed Badea | _________________________ | _____ / _____ / 2026 |
| Youssef Ali Mohamed | _________________________ | _____ / _____ / 2026 |
| Yehia Mohamed Othman | _________________________ | _____ / _____ / 2026 |
| Mohamed Abd El-Nasser | _________________________ | _____ / _____ / 2026 |
| Omar Ayman Mesbah | _________________________ | _____ / _____ / 2026 |
| Belal Mohamed Youness | _________________________ | _____ / _____ / 2026 |

**Supervisor Approval**

Supervisor Name: Prof. Haitham S. Hamza

Supervisor Signature: _________________________ Date: _____ / _____ / 2026

Approval: _________________________

**Department Head Endorsement**

Signature: _________________________ Date: _____ / _____ / 2026
