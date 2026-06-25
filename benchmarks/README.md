# Benchmarking against DVWA / Juice Shop

This package is the scoring harness only — it does not run the agent itself.
Use it once you've actually driven an engagement against a benchmark target
and saved findings via `save_finding`.

## Metrics

Matches the Term 1 proposal's success metrics:
- **ESR** (Engagement Success Rate): fraction of the target's known vulnerability
  categories that the agent found at least one matching finding for.
- **AST** (Attack Success Rate): of the categories the agent appears to have
  attempted (inferred from `technique_used`/`vuln_type`/`tags`), the fraction that
  produced a confirmed finding.
- **FP rate**: fraction of saved findings that don't map to any known category for
  that target — a proxy for false positives, since there's no manually-labeled
  ground truth at the finding level.

Both are heuristic (substring matching on category names against
`vuln_type`/`tags`), not exact — good enough for a directional number to put in
front of the professors, not a rigorous benchmark paper.

## Running it for real

1. Start DVWA (already in `docker-compose.yml`):
   ```bash
   docker compose up dvwa
   ```
2. Create an engagement targeting it:
   ```bash
   curl -X POST localhost:8000/api/engagements \
     -d '{"name": "DVWA benchmark", "target": "http://localhost:8080"}'
   ```
3. Drive a chat session (via the frontend or `/api/chat`) until the agent stops
   finding new things. Let it run through recon, vuln scanning, and exploitation
   (use `analysis_mode: "full_analysis"`, the default — `recon_only` would
   artificially cap the AST/ESR numbers since exploit tools are unavailable).
4. Score it:
   ```python
   from memory.store import MemoryStore
   from benchmarks.scorer import score_engagement

   memory = MemoryStore()
   findings = memory.load_engagement_findings_as_models(engagement_id)
   print(score_engagement(findings, "dvwa"))
   ```

## Adding Juice Shop

Not in `docker-compose.yml` yet. To add it:
```yaml
juice-shop:
  image: bkimminich/juice-shop
  ports:
    - "3000:3000"
```
Then repeat the same steps above with `target=http://localhost:3000` and
`score_engagement(findings, "juice-shop")`. Update `benchmarks/ground_truth.py`
if the Juice Shop version in use has added/renamed challenge categories.
