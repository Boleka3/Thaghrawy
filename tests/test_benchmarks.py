import pytest

from benchmarks.scorer import score_engagement


def test_score_engagement_unknown_target_raises(make_finding):
    with pytest.raises(ValueError):
        score_engagement([make_finding()], "not-a-real-target")


def test_score_engagement_empty_findings_gives_zero_scores():
    result = score_engagement([], "dvwa")
    assert result["esr"] == 0.0
    assert result["ast"] == 0.0
    assert result["fp_rate"] == 0.0
    assert result["total_findings"] == 0


def test_score_engagement_matches_known_category(make_finding):
    findings = [make_finding(vuln_type="SQL Injection", technique_used="sqlmap")]
    result = score_engagement(findings, "dvwa")
    assert result["categories_detected"] == 1
    assert "SQL Injection" in result["detected_categories"]
    assert result["esr"] == pytest.approx(1 / 12, rel=1e-2)
    assert result["fp_rate"] == 0.0


def test_score_engagement_counts_false_positive_for_unmatched_finding(make_finding):
    findings = [make_finding(vuln_type="Totally Made Up Vuln", technique_used="manual")]
    result = score_engagement(findings, "dvwa")
    assert result["categories_detected"] == 0
    assert result["false_positive_count"] == 1
    assert result["fp_rate"] == 1.0


def test_score_engagement_ast_reflects_attempted_categories(make_finding):
    # f-1's technique_used hints at a Brute Force attempt that never produced
    # a matching finding (vuln_type stayed generic); f-2 is a confirmed SQLi
    # finding. Two categories attempted, only one confirmed -> AST < 1.
    findings = [
        make_finding(id="f-1", vuln_type="Other", technique_used="attempted brute force lockout test"),
        make_finding(id="f-2", vuln_type="SQL Injection", technique_used="sqlmap"),
    ]
    result = score_engagement(findings, "dvwa")
    assert result["categories_attempted"] == 2
    assert result["ast"] == pytest.approx(0.5)
