
async def katana(
    url: str,
    depth: int = 1,
    headless: bool = False,
    js_crawl: bool = False,
    known_files: str = None,          # "all" or specific list
    timeout: int = 10,
    concurrency: int = 10,
    delay: float = 0.0,
    scope: list[str] = None,          # regexes for allowed hosts/paths
    fields: str = None,               # custom regex fields
    proxy: str = None,
    silent: bool = True               # default to silent in MCP
) -> dict:
    """
    Crawl a website using Katana.

    Args:
        url: The target URL to crawl (e.g., "https://example.com").
        known_files: Crawls for common sensitive files (robots.txt, sitemap.xml, .env, backup files, etc.).
        timeout: The timeout for each request.
        concurrency: The number of concurrent requests.
        delay: The delay between requests.
        headless: Run Katana in headless mode (no browser UI).
        js_crawl: Enable crawling of JavaScript-rendered content.
        depth: Maximum crawl depth (default is 1).
        silent: Suppress Katana's output (only return results).
        scope: A list of regex patterns to restrict crawling to specific hosts or paths.
        fields: Custom regex patterns to extract specific data from responses.
        proxy: An optional proxy URL (e.g., "http://

    Returns:
        A dictionary containing the crawl results or an error message.
    """

    cmd = ["katana", "-u", url, "-json", "-depth", str(depth)]

    if headless:
        cmd.append("-headless")

    if js_crawl:
        cmd.append("-js-crawl")

    if silent:
        cmd.append("-silent")

    if known_files:
        cmd.extend(["-kf", known_files])

    if timeout:
        cmd.extend(["-timeout", str(timeout)])

    if concurrency:
        cmd.extend(["-c", str(concurrency)])

    if delay:
        cmd.extend(["-delay", str(delay)])

    if scope:
        for s in scope:
            cmd.extend(["-s", s])

    if fields:
        cmd.extend(["-f", fields])

    if proxy:
        cmd.extend(["-p", proxy])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            return {"error": f"Katana failed: {stderr.decode().strip()}"}

        # Parse NDJSON output – each line is one crawled endpoint
        lines = stdout.decode().strip().split('\n')
        results = []
        for line in lines:
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    # Optionally log or skip malformed lines
                    continue

        return {
            "url": url,
            "results": results,
            "count": len(results)
        }
    except FileNotFoundError:
        return {"error": "Katana not found. Please ensure it is installed and in your PATH."}
    except Exception as e:
        return {"error": str(e)}
