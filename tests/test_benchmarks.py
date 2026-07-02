import pytest

from benchmarks.scorer import BenchmarkResult, score_engagement


def test_score_engagement_unknown_target_raises(make_finding):
    with pytest.raises(ValueError):
        score_engagement([make_finding()], "not-a-real-target")


def test_score_engagement_returns_typed_result(make_finding):
    result = score_engagement([make_finding()], "dvwa")
    assert isinstance(result, BenchmarkResult)


def test_score_engagement_empty_findings_gives_zero_scores():
    result = score_engagement([], "dvwa")
    assert result.esr == 0.0
    assert result.ast == 0.0
    assert result.fp_rate == 0.0
    assert result.total_findings == 0
    assert result.detection_rate == 0


def test_score_engagement_matches_known_category(make_finding):
    findings = [make_finding(vuln_type="SQL Injection", technique_used="sqlmap")]
    result = score_engagement(findings, "dvwa")
    assert result.categories_detected == 1
    assert "SQL Injection" in result.detected_categories
    assert result.esr == pytest.approx(1 / 12, rel=1e-2)
    assert result.fp_rate == 0.0
    # SQL Injection maps to OWASP A03 Injection -> 1 distinct OWASP class.
    assert result.detection_rate == 1
    assert result.owasp_categories_detected == ["A03 Injection"]


def test_score_engagement_counts_false_positive_for_unmatched_finding(make_finding):
    findings = [make_finding(vuln_type="Totally Made Up Vuln", technique_used="manual")]
    result = score_engagement(findings, "dvwa")
    assert result.categories_detected == 0
    assert result.false_positive_count == 1
    assert result.fp_rate == 1.0
    assert result.detection_rate == 0


def test_ast_is_average_steps_per_task(make_finding):
    result = score_engagement([make_finding()], "dvwa", total_steps=10, turn_count=4)
    assert result.total_steps == 10
    assert result.turn_count == 4
    assert result.ast == pytest.approx(2.5)


def test_ast_zero_when_no_turns(make_finding):
    result = score_engagement([make_finding()], "dvwa", total_steps=5, turn_count=0)
    assert result.ast == 0.0


def test_detection_rate_counts_distinct_owasp_classes(make_finding):
    # Three findings spanning two OWASP classes: A03 (injection-family) and A07.
    findings = [
        make_finding(id="f1", vuln_type="SQL Injection"),
        make_finding(id="f2", vuln_type="XSS (Reflected)"),  # also A03
        make_finding(id="f3", vuln_type="Brute Force"),      # A07
    ]
    result = score_engagement(findings, "dvwa")
    assert result.detection_rate == 2
    assert set(result.owasp_categories_detected) == {
        "A03 Injection",
        "A07 Identification and Authentication Failures",
    }


def test_meets_targets_true_when_thresholds_satisfied(make_finding):
    result = score_engagement([make_finding()], "dvwa")
    # Hand-construct a passing result to exercise the property logic.
    passing = result.model_copy(update={"esr": 0.8, "fp_rate": 0.1, "detection_rate": 8})
    assert passing.meets_targets is True
    failing = result.model_copy(update={"esr": 0.5, "fp_rate": 0.1, "detection_rate": 8})
    assert failing.meets_targets is False
