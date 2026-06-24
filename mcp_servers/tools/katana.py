"""katana web crawler/spider - discovers endpoints, JS files, APIs, forms."""
from __future__ import annotations

from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_katana(stdout: str) -> dict[str, Any]:
    urls = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
    categories: dict[str, list[str]] = {"js": [], "api": [], "forms": [], "other": []}
    for url in urls:
        lower = url.lower()
        if lower.endswith(".js") or "/js/" in lower:
            categories["js"].append(url)
        elif "/api/" in lower or "api." in lower:
            categories["api"].append(url)
        elif "form" in lower or "submit" in lower or "login" in lower:
            categories["forms"].append(url)
        else:
            categories["other"].append(url)

    return {
        "summary": (
            f"Crawled {len(urls)} endpoints "
            f"({len(categories['js'])} JS, {len(categories['api'])} API, {len(categories['forms'])} forms)"
        ),
        "total_urls": len(urls),
        "categories": {
            "javascript_files": categories["js"][:30],
            "api_endpoints": categories["api"][:30],
            "forms": categories["forms"][:30],
            "other": categories["other"][:50],
        },
    }


def katana_crawl(target: str, depth: int = 3, js_crawl: bool = True) -> dict[str, Any]:
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    cmd = ["katana", "-u", target, "-d", str(depth), "-silent", "-nc"]
    if js_crawl:
        cmd.append("-jc")

    return run_command(cmd, "katana", target, parser=_parse_katana)
