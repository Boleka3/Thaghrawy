from skills import SKILLS, methodology_reference


def test_methodology_reference_includes_every_skill_name_and_a_tool():
    reference = methodology_reference()
    for skill in SKILLS.values():
        assert skill.name in reference
        assert skill.tools, f"skill {skill.name!r} has no tools defined"
        assert skill.tools[0] in reference


def test_methodology_reference_is_a_single_string_with_header():
    reference = methodology_reference()
    assert reference.startswith("METHODOLOGY REFERENCE")
    assert isinstance(reference, str)


def test_report_skill_references_generate_report_tool():
    assert "generate_report" in SKILLS["report"].tools
    assert "save_finding" in SKILLS["report"].tools


def test_methodology_reference_filter_includes_only_matching_skills():
    ref = methodology_reference(skill_filter=["ctf_web", "recon"])
    assert "CTF Web Exploitation" in ref
    assert "Reconnaissance" in ref
    assert "Vulnerability Scanning" not in ref
    assert "Reporting" not in ref


def test_methodology_reference_filter_empty_shows_all():
    ref = methodology_reference(skill_filter=[])
    for skill in SKILLS.values():
        assert skill.name in ref


def test_methodology_reference_filter_none_shows_all():
    ref = methodology_reference(skill_filter=None)
    for skill in SKILLS.values():
        assert skill.name in ref


def test_ctf_web_skill_has_expected_tools():
    ctf = SKILLS["ctf_web"]
    assert "sqlmap_scan" in ctf.tools
    assert "dalfox_scan" in ctf.tools
    assert "ffuf_fuzz" in ctf.tools
    assert "ssrf_test" in ctf.tools
    assert "save_finding" in ctf.tools
    assert "xxe_test" in ctf.tools
    assert "jwt_analyze" in ctf.tools
    assert "csrf_check" in ctf.tools
    assert "headers_audit" in ctf.tools


def test_access_control_skill_has_csrf_check():
    ac = SKILLS["access_control"]
    assert "Access Control" in ac.name
    assert "csrf_check" in ac.tools


def test_security_misconfig_skill_has_headers_audit_and_xxe():
    mc = SKILLS["security_misconfig"]
    assert "Misconfiguration" in mc.name
    assert "headers_audit" in mc.tools
    assert "xxe_test" in mc.tools


def test_filter_includes_new_skills():
    ref = methodology_reference(skill_filter=["access_control", "security_misconfig"])
    assert "Access Control Testing" in ref
    assert "Security Misconfiguration" in ref
    assert "CTF Web Exploitation" not in ref
    assert "Reconnaissance" not in ref
