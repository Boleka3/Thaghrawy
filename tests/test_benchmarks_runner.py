"""Tests for benchmarks/runner.py - the I/O driver around the pure scorer."""
import json
import os

from benchmarks.runner import render_markdown, run_benchmark, write_reports
from benchmarks.scorer import BenchmarkResult, score_engagement


def test_run_benchmark_reads_findings_and_steps(tmp_memory, tmp_engagements, make_finding):
    engagement = tmp_engagements.create(name="DVWA bench", target="http://localhost:8080")
    tmp_engagements.record_steps(engagement.id, 6)
    tmp_engagements.record_steps(engagement.id, 6)  # 12 steps / 2 tasks -> AST 6.0
    tmp_memory.add_finding(make_finding(vuln_type="SQL Injection", engagement_id=engagement.id))

    result = run_benchmark(engagement.id, "dvwa", memory=tmp_memory, manager=tmp_engagements)

    assert isinstance(result, BenchmarkResult)
    assert result.categories_detected == 1
    assert result.ast == 6.0
    assert result.total_steps == 12


def test_run_benchmark_missing_engagement_uses_zero_steps(tmp_memory, tmp_engagements):
    result = run_benchmark("no-such-engagement", "dvwa", memory=tmp_memory, manager=tmp_engagements)
    assert result.total_findings == 0
    assert result.ast == 0.0


def test_render_markdown_includes_all_four_metrics(make_finding):
    result = score_engagement([make_finding(vuln_type="SQL Injection")], "dvwa", total_steps=4, turn_count=2)
    md = render_markdown(result)
    assert "ESR (Exploit Success Rate)" in md
    assert "AST (Average Steps per Task)" in md
    assert "FP Rate" in md
    assert "Detection Rate" in md


def test_write_reports_emits_json_and_markdown(tmp_path, make_finding):
    result = score_engagement([make_finding(vuln_type="SQL Injection")], "dvwa")
    paths = write_reports(result, out_dir=str(tmp_path))

    assert os.path.isfile(paths["json"])
    assert os.path.isfile(paths["markdown"])
    with open(paths["json"]) as f:
        data = json.load(f)
    assert data["target"] == "dvwa"
    assert "esr" in data and "ast" in data and "detection_rate" in data
