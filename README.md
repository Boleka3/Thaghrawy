Thaghrawy

AI-Orchestrated MCP Pentesting Server

Thaghrawy is a modular Multi-Component Platform (MCP) Pentesting Server designed to orchestrate reconnaissance, asset intelligence, and vulnerability workflows through a hybrid Go-powered recon engine and a Python-driven AI decision layer.

Built as an academic graduation project, Thaghrawy is engineered with production scalability and real-world security operations in mind.

🚀 Project Vision

Modern penetration testing often relies on manually chaining multiple tools, producing excessive noise and requiring significant human triage.

Thaghrawy introduces:

Multi-agent orchestration

Context-aware vulnerability execution

Intelligent asset classification

Modular and scalable MCP architecture

It is designed to evolve beyond academic scope into a practical security automation blueprint.

🏗 Architecture Overview
🔹 Recon Engine (Go)

High-performance concurrent asset discovery:

Subfinder

Assetfinder

Httpx

WhatWeb

Gobuster

Built for speed, concurrency, and horizontal scalability.

🔹 MCP Orchestration Layer (Python)

Decision-making and coordination:

Asset classification

Context-aware scanning logic

Workflow orchestration

Risk prioritization

Agent communication

Transforms raw enumeration into structured pentesting intelligence.

🧠 Multi-Agent Structure

Thaghrawy operates through cooperative agents:

Recon Agent

Fingerprinting Agent

Classification Agent

Vulnerability Agent

Reporting Agent

Each agent performs isolated responsibilities while contributing to a unified pentesting workflow.

🎯 Core Objectives

Centralize multiple recon tools under one MCP server

Automate decision-making between tools

Reduce redundant scanning

Provide structured vulnerability workflows

Enable scalable pentesting automation

🔐 OWASP Top 10 Alignment

The architecture supports workflows targeting:

Injection (XSS, SQLi)

Broken Authentication

Security Misconfiguration

Insecure Design

IDOR & Access Control issues

API Security Risks
