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
