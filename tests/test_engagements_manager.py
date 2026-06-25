from engagements.manager import EngagementManager


def test_create_sets_defaults_and_writes_log(tmp_engagements):
    engagement = tmp_engagements.create(name="Acme Web App", target="https://acme.example.com")
    assert engagement.status == "active"
    assert engagement.scope == "https://acme.example.com"
    assert engagement.findings_count == 0

    log = tmp_engagements.read_log(engagement.id)
    assert "Acme Web App" in log
    assert "https://acme.example.com" in log


def test_create_with_explicit_scope_and_tech_stack(tmp_engagements):
    engagement = tmp_engagements.create(
        name="X", target="https://x.com", scope="x.com,api.x.com", tech_stack=["django", "postgres"]
    )
    assert engagement.scope == "x.com,api.x.com"
    assert engagement.tech_stack == ["django", "postgres"]


def test_get_returns_none_for_unknown_id(tmp_engagements):
    assert tmp_engagements.get("does-not-exist") is None


def test_get_returns_persisted_engagement(tmp_engagements):
    created = tmp_engagements.create(name="X", target="https://x.com")
    fetched = tmp_engagements.get(created.id)
    assert fetched == created


def test_list_returns_all_sorted_by_start_date_descending(tmp_engagements):
    tmp_engagements.create(name="Older", target="https://a.com")
    second = tmp_engagements.create(name="Newer", target="https://b.com")
    second_updated = tmp_engagements.update(second.id, start_date="2030-01-01")

    listed = tmp_engagements.list()
    assert listed[0].id == second_updated.id


def test_update_modifies_fields(tmp_engagements):
    created = tmp_engagements.create(name="X", target="https://x.com")
    updated = tmp_engagements.update(created.id, notes="Found SQLi", tech_stack=["flask"])
    assert updated.notes == "Found SQLi"
    assert updated.tech_stack == ["flask"]
    assert tmp_engagements.get(created.id).notes == "Found SQLi"


def test_update_unknown_id_returns_none(tmp_engagements):
    assert tmp_engagements.update("does-not-exist", notes="x") is None


def test_close_sets_status_and_end_date(tmp_engagements):
    created = tmp_engagements.create(name="X", target="https://x.com")
    closed = tmp_engagements.close(created.id)
    assert closed.status == "completed"
    assert closed.end_date is not None


def test_close_unknown_id_returns_none(tmp_engagements):
    assert tmp_engagements.close("does-not-exist") is None


def test_increment_findings_count(tmp_engagements):
    created = tmp_engagements.create(name="X", target="https://x.com")
    updated = tmp_engagements.increment_findings_count(created.id)
    assert updated.findings_count == 1
    updated = tmp_engagements.increment_findings_count(created.id)
    assert updated.findings_count == 2


def test_increment_findings_count_unknown_id_returns_none(tmp_engagements):
    assert tmp_engagements.increment_findings_count("does-not-exist") is None


def test_append_log_and_read_log(tmp_engagements):
    created = tmp_engagements.create(name="X", target="https://x.com")
    tmp_engagements.append_log(created.id, "Extra note")
    log = tmp_engagements.read_log(created.id)
    assert "Extra note" in log


def test_read_log_returns_empty_string_for_unknown_id(tmp_engagements):
    assert tmp_engagements.read_log("does-not-exist") == ""


def test_delete_removes_engagement_and_log(tmp_engagements):
    created = tmp_engagements.create(name="X", target="https://x.com")
    assert tmp_engagements.delete(created.id) is True
    assert tmp_engagements.get(created.id) is None
    assert tmp_engagements.read_log(created.id) == ""


def test_delete_unknown_id_returns_false(tmp_engagements):
    assert tmp_engagements.delete("does-not-exist") is False


def test_independent_instances_use_their_own_base_dir(tmp_path):
    manager_a = EngagementManager(base_dir=str(tmp_path / "a"))
    manager_b = EngagementManager(base_dir=str(tmp_path / "b"))
    created = manager_a.create(name="X", target="https://x.com")
    assert manager_b.get(created.id) is None
