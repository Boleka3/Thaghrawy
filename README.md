# Thaghrawy
## AI-Orchestrated MCP Pentesting Server

Thaghrawy is a modular **Multi-Component Platform (MCP) Pentesting Server** designed to centralize reconnaissance, asset intelligence, and vulnerability assessment workflows within a unified, scalable architecture.

Developed as a graduation project, the system is engineered with production-oriented design principles to ensure extensibility, maintainability, and real-world applicability in offensive security operations.

---

## 📌 Project Overview

Modern penetration testing workflows often rely on manually chaining multiple independent tools. This approach commonly results in:

- Excessive data noise  
- Redundant scanning  
- Limited contextual awareness between tools  
- High manual triage effort  

Thaghrawy addresses these limitations through:

- Structured MCP-based architecture  
- Multi-agent orchestration  
- Context-aware tool execution  
- Modular integration of industry-standard reconnaissance tools  

The platform is designed as a scalable blueprint for intelligent pentesting automation.

---

## 🏗 System Architecture

Thaghrawy is composed of two primary layers:

### 🔹 Reconnaissance Engine (Go)

Implemented in **Go** to leverage concurrency and high-performance execution.

Responsible for:

- Subdomain Enumeration (Subfinder, Assetfinder)  
- Live Host Detection (Httpx)  
- Technology Fingerprinting (WhatWeb)  
- Directory Enumeration (Gobuster)  

This layer focuses on efficient asset discovery and structured output generation.

---

### 🔹 MCP Orchestration Layer (Python)

Implemented in **Python** to enable extensibility and intelligent orchestration logic.

Responsible for:

- Workflow orchestration  
- Agent coordination  
- Asset classification  
- Context-aware vulnerability mapping  
- Risk prioritization  

This layer transforms raw reconnaissance data into structured pentesting intelligence.

---

## 🧠 Multi-Agent Design

The system operates through cooperative functional agents:

1. **Recon Agent**  
2. **Fingerprinting Agent**  
3. **Classification Agent**  
4. **Vulnerability Execution Agent**  
5. **Reporting Agent**  

Each agent performs an isolated responsibility while contributing to a unified pentesting workflow, ensuring scalability and maintainability.

---

## 🎯 Core Objectives

- Centralize reconnaissance tools under a unified MCP server  
- Reduce redundant and unstructured tool chaining  
- Enable context-aware vulnerability workflows  
- Support scalable OWASP Top 10 coverage  
- Establish a foundation for AI-assisted pentesting automation  

---

## 🔐 OWASP Top 10 Alignment

The architecture is designed to support workflows targeting:

- Injection (e.g., XSS, SQL Injection)  
- Broken Authentication  
- Security Misconfiguration  
- Insecure Design  
- Vulnerable Components  
- Access Control Issues (e.g., IDOR patterns)  
- API Security Risks  

Future development phases aim to extend automated detection coverage.

---

🎓 Academic Context

Thaghrawy was developed as a graduation project within the Faculty of Computer Science and Artificial Intelligence (FCAI).

The project aims to bridge academic research and practical offensive security engineering by implementing scalable system architecture principles within a real-world security domain.

⚖ Disclaimer

This project is intended for educational and authorized security testing purposes only.
Users are responsible for ensuring compliance with applicable laws and regulations.

📈 Long-Term Vision

Thaghrawy is intended to evolve beyond academic scope into a modular security orchestration platform capable of integration within enterprise penetration testing and red-team environments.

The architecture supports future expansion in AI-driven prioritization, automated workflow decision-making, and enterprise-grade reporting.

# Install Python Dependencies
pip install -r requirements.txt
