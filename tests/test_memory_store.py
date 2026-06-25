"""Real ChromaDB at a temp path (tmp_memory fixture from conftest.py) -
not mocked, since the embedding model is cached locally and instantiation
is fast. Tests the actual add/search/reconstruct round-trip."""


def test_add_and_load_engagement_findings_round_trip(tmp_memory, make_finding):
    finding = make_finding(id="f-1", engagement_id="eng-1")
    tmp_memory.add_finding(finding)

    loaded = tmp_memory.load_engagement_findings("eng-1")
    assert len(loaded) == 1
    assert loaded[0]["id"] == "f-1"
    assert loaded[0]["metadata"]["title"] == finding.title
    assert loaded[0]["metadata"]["description"] == finding.description
    assert loaded[0]["metadata"]["reproduction_steps"] == finding.reproduction_steps


def test_load_engagement_findings_as_models_reconstructs_full_finding(tmp_memory, make_finding):
    finding = make_finding(
        id="f-1",
        engagement_id="eng-1",
        cvss_score=9.8,
        affected_component="auth-service",
        business_impact="Data exfiltration risk",
        remediation="Use parameterized queries",
        tags=["sqli", "auth"],
    )
    tmp_memory.add_finding(finding)

    [reconstructed] = tmp_memory.load_engagement_findings_as_models("eng-1")
    assert reconstructed.id == "f-1"
    assert reconstructed.title == finding.title
    assert reconstructed.severity == finding.severity
    assert reconstructed.description == finding.description
    assert reconstructed.reproduction_steps == finding.reproduction_steps
    assert reconstructed.cvss_score == 9.8
    assert reconstructed.affected_component == "auth-service"
    assert reconstructed.business_impact == "Data exfiltration risk"
    assert reconstructed.remediation == "Use parameterized queries"
    assert reconstructed.tags == ["sqli", "auth"]


def test_load_engagement_findings_as_models_handles_no_optional_fields(tmp_memory, make_finding):
    finding = make_finding(id="f-1", engagement_id="eng-1")
    tmp_memory.add_finding(finding)

    [reconstructed] = tmp_memory.load_engagement_findings_as_models("eng-1")
    assert reconstructed.cvss_score is None
    assert reconstructed.affected_component is None
    assert reconstructed.business_impact is None
    assert reconstructed.remediation is None
    assert reconstructed.tags == []


def test_load_engagement_findings_filters_by_engagement_id(tmp_memory, make_finding):
    tmp_memory.add_finding(make_finding(id="f-1", engagement_id="eng-1"))
    tmp_memory.add_finding(make_finding(id="f-2", engagement_id="eng-2"))

    assert len(tmp_memory.load_engagement_findings("eng-1")) == 1
    assert len(tmp_memory.load_engagement_findings("eng-2")) == 1
    assert tmp_memory.load_engagement_findings("eng-3") == []


def test_search_findings_returns_relevant_hit_with_similarity(tmp_memory, make_finding):
    tmp_memory.add_finding(make_finding(
        id="f-1", title="SQL Injection in login", description="boolean-based SQLi in the login form"
    ))
    results = tmp_memory.search_findings("SQL injection vulnerability", top_k=3)
    assert len(results) == 1
    assert results[0]["id"] == "f-1"
    assert results[0]["similarity"] is not None


def test_search_findings_scoped_to_engagement_id(tmp_memory, make_finding):
    tmp_memory.add_finding(make_finding(id="f-1", engagement_id="eng-1"))
    tmp_memory.add_finding(make_finding(id="f-2", engagement_id="eng-2"))

    results = tmp_memory.search_findings("SQL Injection", top_k=5, engagement_id="eng-1")
    assert {r["id"] for r in results} == {"f-1"}


def test_add_and_search_techniques(tmp_memory):
    from memory.schemas import Technique

    technique = Technique(
        id="t-1",
        name="sqlmap tamper bypass",
        description="Use sqlmap tamper scripts to bypass a naive WAF",
        platform="web",
        engagement_id="eng-1",
        date="2026-06-01",
    )
    tmp_memory.add_technique(technique)

    results = tmp_memory.search_techniques("bypass a WAF with sqlmap", top_k=3)
    assert len(results) == 1
    assert results[0]["id"] == "t-1"


def test_search_context_combines_findings_and_techniques(tmp_memory, make_finding):
    from memory.schemas import Technique

    tmp_memory.add_finding(make_finding(id="f-1"))
    tmp_memory.add_technique(Technique(
        id="t-1", name="Tamper bypass", description="bypass technique",
        platform="web", engagement_id="eng-1", date="2026-06-01",
    ))

    combined = tmp_memory.search_context("SQL injection", top_k=3)
    assert "findings" in combined
    assert "techniques" in combined


def test_stats_counts_findings_and_techniques(tmp_memory, make_finding):
    from memory.schemas import Technique

    tmp_memory.add_finding(make_finding(id="f-1"))
    tmp_memory.add_finding(make_finding(id="f-2"))
    tmp_memory.add_technique(Technique(
        id="t-1", name="X", description="d", platform="web", engagement_id="eng-1", date="2026-06-01",
    ))

    stats = tmp_memory.stats()
    assert stats == {"findings_count": 2, "techniques_count": 1}


def test_add_finding_upsert_overwrites_existing_id(tmp_memory, make_finding):
    tmp_memory.add_finding(make_finding(id="f-1", title="Original title"))
    tmp_memory.add_finding(make_finding(id="f-1", title="Updated title"))

    loaded = tmp_memory.load_engagement_findings("eng-1")
    assert len(loaded) == 1
    assert loaded[0]["metadata"]["title"] == "Updated title"
