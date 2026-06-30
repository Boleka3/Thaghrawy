import pytest
from pydantic import ValidationError

from memory.schemas import Engagement, Finding, Technique


def test_finding_requires_all_mandatory_fields(make_finding):
    finding = make_finding()
    assert finding.severity == "high"
    assert finding.tags == []


def test_finding_missing_required_field_raises():
    with pytest.raises(ValidationError):
        Finding(
            id="f-1",
            title="X",
            severity="high",
            vuln_type="XSS",
            description="d",
            reproduction_steps="r",
            technique_used="t",
            # missing target/engagement_id/date
        )


def test_finding_rejects_invalid_severity(make_finding):
    with pytest.raises(ValidationError):
        make_finding(severity="apocalyptic")


def test_finding_optional_fields_default_to_none(make_finding):
    finding = make_finding()
    assert finding.cvss_score is None
    assert finding.dread_score is None
    assert finding.affected_component is None
    assert finding.business_impact is None
    assert finding.remediation is None


def test_finding_optional_fields_can_be_set(make_finding):
    finding = make_finding(
        cvss_score=9.8,
        dread_score=8.5,
        affected_component="auth-service",
        business_impact="Data exfiltration risk",
        remediation="Use parameterized queries",
    )
    assert finding.cvss_score == 9.8
    assert finding.dread_score == 8.5
    assert finding.affected_component == "auth-service"
    assert finding.business_impact == "Data exfiltration risk"
    assert finding.remediation == "Use parameterized queries"


def test_finding_rejects_out_of_range_scores(make_finding):
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        make_finding(cvss_score=50)
    with pytest.raises(ValidationError):
        make_finding(dread_score=-3)


def test_technique_requires_mandatory_fields():
    technique = Technique(
        id="t-1",
        name="Tamper script bypass",
        description="Use sqlmap tamper scripts",
        platform="web",
        engagement_id="eng-1",
        date="2026-06-01",
    )
    assert technique.works_against == []
    assert technique.tags == []


def test_technique_missing_required_field_raises():
    with pytest.raises(ValidationError):
        Technique(id="t-1", name="X", description="d", platform="web")


def test_engagement_defaults(make_engagement):
    engagement = make_engagement()
    assert engagement.status == "active"
    assert engagement.end_date is None
    assert engagement.findings_count == 0
    assert engagement.tech_stack == []
    assert engagement.notes == ""


def test_engagement_rejects_invalid_status(make_engagement):
    with pytest.raises(ValidationError):
        make_engagement(status="paused")


def test_engagement_missing_required_field_raises():
    with pytest.raises(ValidationError):
        Engagement(id="e-1", name="X", target="t", scope="s")
