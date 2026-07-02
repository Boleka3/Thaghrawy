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
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union

import config

# Owned local targets, reachable by compose service name from the agent
# container. juice-shop is a Node SPA on :3000; dvwa is a PHP/Apache app on :80
# (302-redirects to login.php unauthenticated) - a useful non-SPA contrast.
_DEFAULT_TARGETS = "juice-shop=http://juice-shop:3000,dvwa=http://dvwa"

# Per-call wall-clock ceiling. The tool wrappers already bound themselves via
# config.RECON_TIMEOUT; this is only a backstop for a truly wedged binary.
PER_CALL_TIMEOUT = int(os.environ.get("SMOKE_PER_CALL_TIMEOUT", str(config.RECON_TIMEOUT + 60)))


@dataclass
class Target:
    name: str   # short label (juice-shop / dvwa)
    url: str    # full base URL (http://host:port)
    host: str   # bare hostname for host-oriented scanners
    port: str   # port as a string for nmap/naabu/masscan/testssl


def _parse_targets(spec: str) -> list[Target]:
    """Parse a 'name=url,name=url' spec into Target objects, deriving host/port
    from each URL."""
    import re as _re

    targets = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, _, url = chunk.partition("=")
        url = (url or name).strip()
        m = _re.match(r"^\w+://([^/:]+)(?::(\d+))?", url)
        host = m.group(1) if m else url
        port = (m.group(2) if m and m.group(2) else "80")
        targets.append(Target(name=name.strip(), url=url.rstrip("/"), host=host, port=port))
    return targets


# A tiny wordlist so ffuf/gobuster stay snappy against the local host instead of
# firing thousands of requests from the default dirb list.
_SMOKE_WORDLIST = os.path.join(config.WORKSPACE_DIR, "_smoke_wordlist.txt")
_WORDLIST_ENTRIES = ["rest", "api", "ftp", "assets", "robots.txt", "sitemap.xml", "public"]

# Plumbing signatures — these in an error string mean OUR wiring is broken,
# not that the target legitimately had nothing to report.
_PLUMBING_SIGNS = (
    "raised:",                    # ToolRegistry caught a Python exception
    "unexpected keyword",         # wrapper signature missing a kwarg
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


def _profiles(t: Target) -> list[Profile]:
    """Build the per-target profile matrix. Generic paths/params are used so the
    same matrix runs against any web target (juice-shop SPA or dvwa PHP app);
    the goal is plumbing coverage, not target-specific exploitation depth."""
    url, host, port = t.url, t.host, t.port
    return [
        # ── recon: subdomains / DNS (expected legit-empty on a docker name) ──
        ("amass_scan", {"domain": host, "mode": "passive"}, "passive only"),
        ("subfinder_scan", {"domain": host}, "no subdomains expected"),
        ("assetfinder_scan", {"domain": host}, "no subdomains expected"),
        ("dnsx_scan", {"target": host}, "resolve docker name"),
        ("whois_lookup", {"domain": host}, "no whois for docker name"),
        # ── recon: web/host probing ─────────────────────────────────────────
        ("httpx_scan", {"domains": [f"{host}:{port}"]}, "list arg"),
        ("httpx_scan", {"domains": f"{host}:{port}, {host}"}, "comma-string arg (LLM-style)"),
        ("web_tech_detect", {"target": url}, "whatweb"),
        ("wafw00f_scan", {"target": url}, "waf fingerprint"),
        ("katana_crawl", {"target": url, "depth": 1}, "shallow crawl"),
        ("nuclei_scan", {"target": url, "tags": "tech"}, "tech templates only"),
        ("ffuf_fuzz", {"url": f"{url}/FUZZ", "wordlist": _SMOKE_WORDLIST}, "tiny wordlist"),
        ("gobuster_scan", {"mode": "dir", "target": url, "wordlist": _SMOKE_WORDLIST}, "tiny wordlist"),
        ("arjun_scan", {"url": f"{url}/", "method": "GET"}, "param discovery"),
        # ── recon: ports ────────────────────────────────────────────────────
        ("nmap_scan", {"target": host, "ports": port}, "explicit open port"),
        ("nmap_scan", {"target": f"{url}/x", "top_ports": "100"}, "URL-strip + top_ports (LLM-style)"),
        ("naabu_scan", {"target": host, "top_ports": "100"}, "top ports"),
        ("masscan_scan", {"target": host, "ports": port}, "needs raw sockets"),
        ("masscan_scan", {"target": host, "top_ports": port}, "top_ports alias (LLM-style)"),
        # ── recon: N/A-for-target (must fail CLEANLY, not crash) ────────────
        ("testssl_scan", {"target": f"{host}:{port}"}, "plain http, no TLS"),
        ("wpscan_scan", {"target": url}, "not WordPress"),
        ("enum4linux_scan", {"target": host}, "no SMB"),
        ("searchsploit_lookup", {"query": "apache"}, "offline exploitdb"),
        # ── recon: kill-chain probes ────────────────────────────────────────
        ("upload_test", {"url": f"{url}/"}, "upload probe"),
        ("ssrf_test", {"url": f"{url}/?url=http://127.0.0.1", "param": "url"}, "ssrf probe"),
        # ── recon: workspace utilities (chained off produced files) ─────────
        ("list_workspace", {}, "list produced files"),
        ("read_file", lambda ctx: {"filename": ctx.get("produced_file", "_smoke_wordlist.txt")},
         "read a returned workspace path"),
        ("grep_workspace", {"pattern": "http", "filename": ""}, "grep across workspace"),
        # ── platform tools ──────────────────────────────────────────────────
        ("http_request", {"url": url, "method": "GET"}, "generic GET"),
        ("parse_tool_output", {"tool_name": "nmap", "raw_output": f"{port}/tcp open http"}, "output filter"),
        ("shell", {"command": "id"}, "guardrails + logging"),
        ("search_memory", {"query": "sql injection", "top_k": 2}, "semantic recall"),
        ("save_finding", lambda ctx: {"finding": {
            "title": "smoke-test finding", "severity": "info", "vuln_type": "smoke",
            "description": "harness self-test", "reproduction_steps": "n/a",
            "technique_used": "smoke", "target": url,
            "engagement_id": ctx["engagement_id"], "tags": ["smoke"],
        }}, "persist a finding"),
        ("save_technique", lambda ctx: {"technique": {
            "name": "smoke-technique", "description": "harness self-test",
            "works_against": ["web"], "platform": "web",
            "engagement_id": ctx["engagement_id"], "tags": ["smoke"],
        }}, "persist a technique"),
        ("load_engagement_context", lambda ctx: {"engagement_id": ctx["engagement_id"]}, "reload findings"),
        ("generate_report", lambda ctx: {"engagement_id": ctx["engagement_id"]}, "build both reports"),
        # ── exploit tools (bounded; owned target) — incl. OWASP A03 additions ─
        ("sqlmap_scan", {"url": f"{url}/?id=1", "batch": True}, "SQLi, one param"),
        ("dalfox_scan", {"url": f"{url}/?q=test"}, "XSS (A03)"),
        ("wapiti_scan", {"url": f"{url}/", "modules": "xss,sql"}, "broad OWASP web sweep"),
        ("nikto_scan", {"target": url}, "quick web scan"),
        ("hydra_bruteforce", {"target": host, "service": "http-get", "user": "admin",
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

    # A binary that isn't on PATH is a *deployment* gap (tool not installed in
    # this image), not a wrapper plumbing bug - surface it distinctly so an
    # optional/release-installed tool pending a rebuild doesn't fail the gate.
    if "not found on path" in low or low.startswith("binary for"):
        return "MISSING", err

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


# ── skills coverage ─────────────────────────────────────────────────────────

def _check_skills_coverage(registry) -> tuple[list[str], list[str]]:
    """Cross-check skills.py's methodology against the live registry. A skill
    that names a non-registered tool is a real bug (the system prompt tells the
    model to call something that doesn't exist). Returns (broken_refs,
    tools_in_no_skill)."""
    from skills import SKILLS

    registered = set(registry.names())
    referenced: set[str] = set()
    broken: list[str] = []
    for key, skill in SKILLS.items():
        for tool in skill.tools:
            referenced.add(tool)
            if tool not in registered:
                broken.append(f"{key} -> {tool}")
    unreferenced = sorted(registered - referenced)
    return broken, unreferenced


# ── driver ──────────────────────────────────────────────────────────────────

async def _run_target(registry, target: Target) -> list[tuple[str, str, str, float, str]]:
    from engagements.manager import EngagementManager

    engagement = EngagementManager().create(
        name=f"tool-smoke-{target.name}", target=target.url, scope=target.url
    )
    os.environ["THAGHRAWY_ENGAGEMENT_ID"] = engagement.id
    ctx: dict[str, Any] = {"engagement_id": engagement.id, "produced_file": ""}
    rows: list[tuple[str, str, str, float, str]] = []

    print(f"\n## {target.name}  ({target.url})  engagement {engagement.id[:8]}\n")
    for name, arg_spec, note in _profiles(target):
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
        if verdict in ("BUG", "MISSING", "REVIEW", "FAILED", "ERR", "TIMEOUT"):
            print(f"          └─ {detail}")
    return rows


async def _run(targets: list[Target]) -> int:
    os.makedirs(config.WORKSPACE_DIR, exist_ok=True)
    with open(_SMOKE_WORDLIST, "w") as fh:
        fh.write("\n".join(_WORDLIST_ENTRIES) + "\n")

    from core.tools import build_default_registry
    from memory.store import MemoryStore

    memory = MemoryStore()
    # One full registry (all tools) drives every target; a throwaway engagement
    # id is fine here since per-target engagements are created in _run_target.
    registry = build_default_registry(memory, "tool-smoke", include_exploit_tools=True)

    print(f"# tool-smoke — {len(targets)} target(s): {', '.join(t.name for t in targets)}")

    all_rows: list[tuple[str, str, str, float, str]] = []
    per_target_bugs: dict[str, int] = {}
    for target in targets:
        rows = await _run_target(registry, target)
        all_rows += rows
        per_target_bugs[target.name] = sum(1 for r in rows if r[1] == "BUG")

    # ── skills coverage ──
    broken, unreferenced = _check_skills_coverage(registry)
    print("\n## Skills coverage (skills.py ↔ registry)\n")
    if broken:
        print("  BROKEN skill references (tool named in a skill but NOT registered):")
        for b in broken:
            print(f"    - {b}")
    else:
        print("  All skill tool references resolve to a registered tool ✓")
    if unreferenced:
        print(f"  Registered tools in no skill (visibility gap): {', '.join(unreferenced)}")

    # ── summary ──
    bugs = [r for r in all_rows if r[1] == "BUG"]
    missing = sorted({r[0] for r in all_rows if r[1] == "MISSING"})
    review = [r for r in all_rows if r[1] in ("REVIEW", "FAILED", "ERR", "TIMEOUT")]
    ok = [r for r in all_rows if r[1] in ("OK", "BLOCKED")]
    print("\n" + "=" * 70)
    for name, n in per_target_bugs.items():
        print(f"  {name}: {n} BUG(s)")
    print(f"  TOTAL  OK/BLOCKED: {len(ok)}   REVIEW: {len(review)}   MISSING: {len(missing)}   "
          f"BUG: {len(bugs)}   SKILLS-BROKEN: {len(broken)}   (calls {len(all_rows)})")
    if bugs:
        print("\n  PLUMBING BUGS (fix these):")
        for name, _, note, _, detail in bugs:
            print(f"    - {name} [{note}]: {detail}")
    if missing:
        print(f"\n  NOT INSTALLED in this image (activate on rebuild): {', '.join(missing)}")
    if review:
        print("\n  NEEDS MANUAL REVIEW (may be benign N/A-target failures):")
        for name, verdict, note, _, detail in review:
            print(f"    - {name} [{verdict}] {note}: {detail}")
    print("=" * 70)
    return 1 if (bugs or broken) else 0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Live tool-smoke harness")
    parser.add_argument(
        "--targets", default=os.environ.get("SMOKE_TARGETS", _DEFAULT_TARGETS),
        help="Comma-separated name=url list (default: juice-shop + dvwa)",
    )
    args = parser.parse_args()
    targets = _parse_targets(args.targets)
    return asyncio.run(_run(targets))


if __name__ == "__main__":
    sys.exit(main())
