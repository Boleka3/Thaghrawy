# Benchmarking against DVWA / Juice Shop

This package is the scoring harness only — it does not run the agent itself.
Use it once you've actually driven an engagement against a benchmark target
and saved findings via `save_finding`.

## Metrics

The four metrics from `Thaghrawy_Project.pdf` (Table 4.2):
- **ESR** (Exploit Success Rate): fraction of the target's known vulnerability
  categories for which the agent produced at least one confirmed finding. A
  persisted Finding represents a confirmed/exploited vulnerability (the agent only
  saves findings after confirmation). **Target: ≥ 0.70.**
- **AST** (Average Steps per Task): mean number of tool-execution steps the agent
  took per task (turn). Sourced from the engagement's `total_steps`/`turn_count`
  counters (instrumented in `core/agent.py`), not from findings. Lower = fewer
  "rabbit holes". **Target: minimize.**
- **FP Rate**: fraction of saved findings that don't map to any known category for
  that target — a proxy for false positives, since there's no manually-labeled
  ground truth at the finding level. **Target: ≤ 0.15.**
- **Detection Rate**: number of distinct OWASP Top 10 (2021) classes detected,
  via `ground_truth.py::CATEGORY_TO_OWASP`. **Target: 8 / 10.**

Category matching is heuristic (case-insensitive substring of category names
against `vuln_type`/`tags`), not exact — good enough for a directional number to
put in front of the professors, not a rigorous benchmark paper.

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
4. Score it with the runner (computes all four metrics and writes a JSON +
   Markdown report under `REPORTS_DIR`):
   ```bash
   python -m benchmarks.runner <engagement_id> dvwa
   ```
   Or call the pure scorer directly:
   ```python
   from memory.store import MemoryStore
   from engagements.manager import EngagementManager
   from benchmarks.scorer import score_engagement

   memory = MemoryStore()
   eng = EngagementManager().get(engagement_id)
   findings = memory.load_engagement_findings_as_models(engagement_id)
   print(score_engagement(findings, "dvwa", total_steps=eng.total_steps, turn_count=eng.turn_count))
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
