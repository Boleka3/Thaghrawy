from prompt_builder import build_system_prompt


def test_build_system_prompt_with_target_only():
    prompt = build_system_prompt("https://acme.example.com")
    assert "SCOPE: https://acme.example.com" in prompt
    assert "No relevant memory found for this query." in prompt
    assert "METHODOLOGY REFERENCE" in prompt


def test_build_system_prompt_includes_finding_and_technique_hits():
    memory_hits = {
        "findings": [{
            "id": "f-1",
            "similarity": 0.87,
            "metadata": {"title": "SQLi", "severity": "high", "vuln_type": "SQLi", "engagement_id": "eng-1"},
            "document": "SQL injection in login form",
        }],
        "techniques": [{
            "id": "t-1",
            "similarity": 0.5,
            "metadata": {"name": "sqlmap tamper", "works_against": "MySQL"},
            "document": "Use tamper scripts to bypass WAF",
        }],
    }
    prompt = build_system_prompt("https://acme.example.com", memory_hits=memory_hits)
    assert "past finding, similarity=0.87" in prompt
    assert "SQLi" in prompt
    assert "past technique, similarity=0.50" in prompt
    assert "sqlmap tamper" in prompt


def test_build_system_prompt_empty_memory_hits_shows_default_message():
    prompt = build_system_prompt("https://acme.example.com", memory_hits={"findings": [], "techniques": []})
    assert "No relevant memory found for this query." in prompt


def test_build_system_prompt_findings_only_no_techniques():
    memory_hits = {
        "findings": [{"id": "f-1", "similarity": 0.9, "metadata": {"title": "XSS"}, "document": "reflected xss"}],
        "techniques": [],
    }
    prompt = build_system_prompt("https://acme.example.com", memory_hits=memory_hits)
    assert "past finding" in prompt
    assert "past technique" not in prompt


def test_build_system_prompt_includes_extra_sections():
    prompt = build_system_prompt("https://acme.example.com", extra_sections=["EXTRA SECTION ONE", "EXTRA TWO"])
    assert "EXTRA SECTION ONE" in prompt
    assert "EXTRA TWO" in prompt


def test_build_system_prompt_without_extra_sections_omits_nothing_unexpected():
    prompt = build_system_prompt("https://acme.example.com", extra_sections=None)
    assert prompt.count("SCOPE:") == 1
