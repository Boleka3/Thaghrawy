"""Live tool-smoke harness — exercise every registered agent tool against a
local, owned target (OWASP Juice Shop) through the agent's OWN execution path.

Why this exists
---------------
Every unit test in tests/ mocks `subprocess.run`, so no test ever runs a real
binary against a real target. Real-CLI bugs — wrong binary name, URL-vs-host
arg handling, kwargs the LLM invents (`top_ports`), doubled workspace paths —
slip straight through to live engagements. This harness closes that gap: it
builds the real `ToolRegistry` (`core.tools.build_default_registry`) and drives
every tool through `registry.execute()` — the exact path the agent uses — with
realistic AND deliberately LLM-sloppy args, then classifies each result.

It is NOT a pytest test (it needs live binaries + a running target); it is a
standalone gate meant to be run in the container:

    docker compose exec -T agent python3 -m scripts.tool_smoke

Exit code is non-zero if any tool trips a plumbing BUG (uncaught exception,
missing binary, bad kwarg). Expected-empty results on an N/A target (no
subdomains, no TLS, no SMB) are NOT bugs — the classifier's whole job is to
tell those apart.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import Any, Callable, Optional, Union

import config

TARGET_URL = os.environ.get("SMOKE_TARGET_URL", "http://juice-shop:3000")
TARGET_HOST = os.environ.get("SMOKE_TARGET_HOST", "juice-shop")
# Per-call wall-clock ceiling. The tool wrappers already bound themselves via
# config.RECON_TIMEOUT; this is only a backstop for a truly wedged binary.
PER_CALL_TIMEOUT = int(os.environ.get("SMOKE_PER_CALL_TIMEOUT", str(config.RECON_TIMEOUT + 60)))

# A tiny wordlist so ffuf/gobuster stay snappy against the local host instead of
# firing thousands of requests from the default dirb list.
_SMOKE_WORDLIST = os.path.join(config.WORKSPACE_DIR, "_smoke_wordlist.txt")
_WORDLIST_ENTRIES = ["rest", "api", "ftp", "assets", "robots.txt", "sitemap.xml", "public"]

# Plumbing signatures — these in an error string mean OUR wiring is broken,
# not that the target legitimately had nothing to report.
_PLUMBING_SIGNS = (
    "raised:",                    # ToolRegistry caught a Python exception
    "unexpected keyword",         # wrapper signature missing a kwarg
    "not found on path",          # _common.run_command FileNotFoundError
    "binary for",                 # same, our own message
    "command not found",
    "no such file or directory",
    "traceback (most recent call",
    "unrecognized arguments",
    "typeerror", "attributeerror", "keyerror", "nameerror", "modulenotfounderror",
    "positional argument",
)


# ── argument profiles ───────────────────────────────────────────────────────
# Each entry: (tool_name, args, note). `args` may be a dict, or a callable
# taking the shared run-context (to chain off a file a prior tool produced).
Profile = tuple[str, Union[dict, Callable[[dict], dict]], str]


def _profiles() -> list[Profile]:
    return [
        # ── recon: subdomains / DNS (expected legit-empty on a docker name) ──
        ("amass_scan", {"domain": TARGET_HOST, "mode": "passive"}, "passive only"),
        ("subfinder_scan", {"domain": TARGET_HOST}, "no subdomains expected"),
        ("assetfinder_scan", {"domain": TARGET_HOST}, "no subdomains expected"),
        ("dnsx_scan", {"target": TARGET_HOST}, "resolve docker name"),
        ("whois_lookup", {"domain": TARGET_HOST}, "no whois for docker name"),
        # ── recon: web/host probing ─────────────────────────────────────────
        ("httpx_scan", {"domains": [f"{TARGET_HOST}:3000"]}, "list arg"),
        ("httpx_scan", {"domains": f"{TARGET_HOST}:3000, {TARGET_HOST}"}, "comma-string arg (LLM-style)"),
        ("web_tech_detect", {"target": TARGET_URL}, "whatweb"),
        ("wafw00f_scan", {"target": TARGET_URL}, "waf fingerprint"),
        ("katana_crawl", {"target": TARGET_URL, "depth": 1}, "shallow crawl"),
        ("nuclei_scan", {"target": TARGET_URL, "tags": "tech"}, "tech templates only"),
        ("ffuf_fuzz", {"url": f"{TARGET_URL}/FUZZ", "wordlist": _SMOKE_WORDLIST}, "tiny wordlist"),
        ("gobuster_scan", {"mode": "dir", "target": TARGET_URL, "wordlist": _SMOKE_WORDLIST}, "tiny wordlist"),
        ("arjun_scan", {"url": f"{TARGET_URL}/rest/products/search", "method": "GET"}, "param discovery"),
        # ── recon: ports ────────────────────────────────────────────────────
        ("nmap_scan", {"target": TARGET_HOST, "ports": "3000"}, "explicit open port"),
        ("nmap_scan", {"target": f"{TARGET_URL}/x", "top_ports": "100"}, "URL-strip + top_ports (LLM-style)"),
        ("naabu_scan", {"target": TARGET_HOST, "top_ports": "100"}, "top ports"),
        ("masscan_scan", {"target": TARGET_HOST, "ports": "3000"}, "needs raw sockets"),
        ("masscan_scan", {"target": TARGET_HOST, "top_ports": "3000"}, "top_ports alias (LLM-style)"),
        # ── recon: N/A-for-target (must fail CLEANLY, not crash) ────────────
        ("testssl_scan", {"target": f"{TARGET_HOST}:3000"}, "plain http, no TLS"),
        ("wpscan_scan", {"target": TARGET_URL}, "not WordPress"),
        ("enum4linux_scan", {"target": TARGET_HOST}, "no SMB"),
        ("searchsploit_lookup", {"query": "juice shop"}, "offline exploitdb"),
        # ── recon: kill-chain probes ────────────────────────────────────────
        ("upload_test", {"url": f"{TARGET_URL}/api/Users"}, "upload probe"),
        ("ssrf_test", {"url": f"{TARGET_URL}/redirect?to=test", "param": "to"}, "ssrf probe"),
        # ── recon: workspace utilities (chained off produced files) ─────────
        ("list_workspace", {}, "list produced files"),
        ("read_file", lambda ctx: {"filename": ctx.get("produced_file", "_smoke_wordlist.txt")},
         "read a returned workspace path"),
        ("grep_workspace", {"pattern": "http", "filename": ""}, "grep across workspace"),
        # ── platform tools ──────────────────────────────────────────────────
        ("http_request", {"url": TARGET_URL, "method": "GET"}, "generic GET"),
        ("parse_tool_output", {"tool_name": "nmap", "raw_output": "3000/tcp open http"}, "output filter"),
        ("search_memory", {"query": "sql injection", "top_k": 2}, "semantic recall"),
        ("save_finding", lambda ctx: {"finding": {
            "title": "smoke-test finding", "severity": "info", "vuln_type": "smoke",
            "description": "harness self-test", "reproduction_steps": "n/a",
            "technique_used": "smoke", "target": TARGET_URL,
            "engagement_id": ctx["engagement_id"], "tags": ["smoke"],
        }}, "persist a finding"),
        ("save_technique", lambda ctx: {"technique": {
            "name": "smoke-technique", "description": "harness self-test",
            "works_against": ["web"], "platform": "web",
            "engagement_id": ctx["engagement_id"], "tags": ["smoke"],
        }}, "persist a technique"),
        ("load_engagement_context", lambda ctx: {"engagement_id": ctx["engagement_id"]}, "reload findings"),
        ("generate_report", lambda ctx: {"engagement_id": ctx["engagement_id"]}, "build both reports"),
        # ── exploit tools (bounded; owned target) ───────────────────────────
        ("sqlmap_scan", {"url": f"{TARGET_URL}/rest/products/search?q=test", "batch": True}, "one param"),
        ("nikto_scan", {"target": TARGET_URL}, "quick web scan"),
        ("hydra_bruteforce", {"target": TARGET_HOST, "service": "http-get", "user": "admin",
                              "wordlist": _SMOKE_WORDLIST}, "tiny wordlist"),
        ("linux_privesc_check", {}, "local recon in container"),
        ("credential_search", {}, "scan workspace for secrets"),
    ]


# ── classification ──────────────────────────────────────────────────────────

def _as_dict(result: Any) -> Optional[dict]:
    if isinstance(result, dict):
        return result
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
            return parsed if isinstance(parsed, dict) else {"_value": parsed}
        except (ValueError, TypeError):
            return None
    return None


def _summary(parsed: dict) -> str:
    interesting = [
        "alive_count", "open_ports", "subdomains", "subdomain_count", "hosts",
        "urls", "results", "findings", "params", "technologies", "record_count",
        "status_code", "id", "full_output_file", "subdomain_list_file",
        "technical", "executive",
    ]
    bits = []
    for k in interesting:
        if k in parsed:
            v = parsed[k]
            bits.append(f"{k}={len(v)}" if isinstance(v, (list, dict)) else f"{k}={str(v)[:48]}")
    return " ".join(bits) if bits else f"keys={list(parsed.keys())[:6]}"


def _produced_file(parsed: dict) -> Optional[str]:
    """Return a workspace path this tool wrote, so read_file can be chained off
    exactly the kind of value the agent gets handed back."""
    for k in ("subdomain_list_file", "full_output_file"):
        v = parsed.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def classify(result: Any) -> tuple[str, str]:
    parsed = _as_dict(result)
    if parsed is None:
        return "REVIEW", f"non-json output: {str(result)[:150]}"

    err = str(parsed.get("error", "") or "")
    low = err.lower()

    if any(sign in low for sign in _PLUMBING_SIGNS):
        return "BUG", err

    status = parsed.get("status")
    if status in ("success", "saved", "completed"):
        return "OK", _summary(parsed)
    if status == "blocked":
        return "BLOCKED", str(parsed.get("reason", ""))
    if status == "failed":
        # non-zero exit: usually "nothing found" on an N/A target, occasionally
        # a bad-arg bug. Surface the stderr preview for manual eyeballing.
        return "FAILED", str(parsed.get("error_preview") or parsed.get("error") or "")[:200]
    if status == "error":
        if "timed out" in low:
            return "TIMEOUT", err
        return "ERR", err or _summary(parsed)
    # dict tools without a `status` field (http_request, search_memory, …)
    if err:
        return "ERR", err
    return "OK", _summary(parsed)


# ── driver ──────────────────────────────────────────────────────────────────

async def _run() -> int:
    os.makedirs(config.WORKSPACE_DIR, exist_ok=True)
    with open(_SMOKE_WORDLIST, "w") as fh:
        fh.write("\n".join(_WORDLIST_ENTRIES) + "\n")

    from core.tools import build_default_registry
    from engagements.manager import EngagementManager
    from memory.store import MemoryStore

    memory = MemoryStore()
    engagement = EngagementManager().create(
        name="tool-smoke", target=TARGET_URL, scope=TARGET_URL
    )
    os.environ["THAGHRAWY_ENGAGEMENT_ID"] = engagement.id
    registry = build_default_registry(memory, engagement.id, include_exploit_tools=True)

    ctx: dict[str, Any] = {"engagement_id": engagement.id, "produced_file": ""}
    rows: list[tuple[str, str, str, float, str]] = []

    print(f"# tool-smoke against {TARGET_URL} (engagement {engagement.id[:8]})\n")
    for name, arg_spec, note in _profiles():
        args = arg_spec(ctx) if callable(arg_spec) else dict(arg_spec)
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(registry.execute(name, args), timeout=PER_CALL_TIMEOUT)
        except asyncio.TimeoutError:
            result = {"status": "error", "error": f"harness timeout after {PER_CALL_TIMEOUT}s"}
        elapsed = time.monotonic() - start

        verdict, detail = classify(result)
        parsed = _as_dict(result) or {}
        produced = _produced_file(parsed)
        if produced:
            ctx["produced_file"] = produced

        rows.append((name, verdict, note, elapsed, detail))
        print(f"[{verdict:<7}] {name:<22} {elapsed:6.1f}s  {note}")
        if verdict in ("BUG", "REVIEW", "FAILED", "ERR", "TIMEOUT"):
            print(f"          └─ {detail}")

    # ── summary ──
    bugs = [r for r in rows if r[1] == "BUG"]
    review = [r for r in rows if r[1] in ("REVIEW", "FAILED", "ERR", "TIMEOUT")]
    ok = [r for r in rows if r[1] in ("OK", "BLOCKED")]
    print("\n" + "=" * 70)
    print(f"  OK/BLOCKED: {len(ok)}   REVIEW: {len(review)}   BUG: {len(bugs)}   (total {len(rows)})")
    if bugs:
        print("\n  PLUMBING BUGS (fix these):")
        for name, _, note, _, detail in bugs:
            print(f"    - {name} [{note}]: {detail}")
    if review:
        print("\n  NEEDS MANUAL REVIEW (may be benign N/A-target failures):")
        for name, verdict, note, _, detail in review:
            print(f"    - {name} [{verdict}] {note}: {detail}")
    print("=" * 70)
    return 1 if bugs else 0


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
