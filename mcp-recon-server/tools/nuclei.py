
async def nuclei(
    url: str = None,                         # Single target URL

    # Path to file with multiple URLs (for -l)
    targets_file: str = None,

    # -t flag(s): list of paths or a single string
    templates: list[str] | str = None,

    tags: list[str] | str = None,           # Comma-sep string or list of tags

    exclude_tags: list[str] | str = None,   # -etags

    severity: str = None,                   # e.g., "critical,high,medium"

    exclude_severities: str = None,         # e.g., "low,info"

    headless: bool = False,

    concurrency: int = 10,

    # requests/sec; None → Nuclei default (150)
    rate_limit: int | None = None,

    timeout: int = 10,                      # per-request timeout (seconds)

    # max total scan time (seconds), optional
    max_time: int | None = None,

    silent: bool = True,                    # always -silent

    output_json: bool = True,               # always -json

    no_interactsh: bool = False,            # disable OOB detection if needed
) -> dict:
    """
    Run Nuclei against a target URL or list of URLs.

    Args:
        url: A single target URL (e.g., "https://example.com").
        targets_file: Path to a file containing multiple URLs (one per line).
        templates: A template path or list of template paths to use for scanning.
        tags: A comma-separated string or list of tags to include in the scan.
        exclude_tags: A comma-separated string or list of tags to exclude from the scan.
        severity: Comma-separated string of severities to include (e.g., "critical,high").
        exclude_severities: Comma-separated string of severities to exclude (e.g., "low,info").
        headless: Run Nuclei in headless mode (no browser UI).
        concurrency: Number of concurrent requests.
        rate_limit: Requests per second (None for Nuclei default).
        timeout: Per-request timeout in seconds.
        max_time: Maximum total scan time in seconds (optional).
        silent: Suppress Nuclei's output (only return results).
        output_json: Always output results in JSON format.
        no_interactsh: Disable OOB detection if needed.

    Returns:
        A dictionary containing the scan results or an error message.
    """

    # Base Command
    cmd = ["nuclei", "-json"]

    # ======== Command Building ========

    # Target specification: URL or file
    if url is not None:
        cmd.extend(["-u", url])
    elif targets_file is not None:
        cmd.extend(["-l", targets_file])
    else:
        return {"error": "No target specified. Provide 'url' or 'targets_file'."}

    # Always silent (MCP tool shouldn’t print banners)
    cmd.append("-silent")

    # Concurrency
    cmd.extend(["-c", str(concurrency)])

    # Rate limit only if explicitly set (None -> skip flag, > 0 -> use value)
    if rate_limit is not None and rate_limit > 0:
        cmd.extend(["-rl", str(rate_limit)])

    # Single string or list for tags
    if tags:
        if isinstance(tags, list):
            cmd.extend(["-tags", ",".join(tags)])
        else:
            cmd.extend(["-tags", tags])

    # Template(s): string or list
    if template:
        if isinstance(template, list):
            for t in template:
                cmd.extend(["-t", t])
        else:
            cmd.extend(["-t", template])

    # Severity (string, e.g., "critical,high")
    if severity:
        cmd.extend(["-severity", severity])

    # Headless
    if headless:
        cmd.append("-headless")

    # Per‑request timeout (important!)
    cmd.extend(["-timeout", str(timeout)])

    # Global timeout (optional)
    if max_time:
        cmd.extend(["-max-time", str(max_time)])

    # Interactsh control
    if no_interactsh:
        cmd.append("-no-interactsh")

    # ======= Command Execution =======
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            return {"error": f"Nuclei failed: {stderr.decode().strip()}"}

        # Parse NDJSON output – each line is one vulnerability finding
        lines = stdout.decode().strip().split('\n')
        results = []
        for line in lines:
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    # Skip lines that aren't valid JSON (e.g., banner if -silent was omitted)
                    continue

        return {
            "url": url,
            "results": results,
            "count": len(results)
        }

    except FileNotFoundError:
        return {"error": "Nuclei not found. Please ensure it is installed and in your PATH."}
    except Exception as e:
        return {"error": str(e)}
