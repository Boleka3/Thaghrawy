import json

from memory.schemas import Technique
from training.exporter import (
    build_dataset,
    finding_to_example,
    technique_to_example,
    trajectory_to_examples,
)


# ── findings ──


def test_finding_to_messages_example(make_finding):
    f = make_finding(remediation="Use parameterized queries.")
    ex = finding_to_example(f, fmt="messages")
    roles = [m["role"] for m in ex["messages"]]
    assert roles == ["system", "user", "assistant"]
    assert f.target in ex["messages"][1]["content"]
    completion = json.loads(ex["messages"][2]["content"])
    assert completion["vuln_type"] == f.vuln_type
    assert completion["remediation"] == "Use parameterized queries."


def test_finding_to_sft_example(make_finding):
    ex = finding_to_example(make_finding(), fmt="sft")
    assert set(ex) == {"prompt", "completion"}


# ── techniques ──


def test_technique_to_example():
    t = Technique(
        id="t1", name="JWT alg=none bypass", description="Strip the signature.",
        works_against=["JWT"], platform="api", engagement_id="e", date="2026-06-01",
    )
    ex = technique_to_example(t, fmt="messages")
    completion = json.loads(ex["messages"][2]["content"])
    assert completion["name"] == "JWT alg=none bypass"
    assert completion["works_against"] == ["JWT"]


# ── trajectory -> preference pairs ──


def test_edit_record_becomes_preference_pair():
    records = [{
        "tool": "sqlmap_scan",
        "proposed_arguments": {"url": "http://t"},
        "verdict": "edit",
        "final_arguments": {"url": "http://t/login?id=1"},
    }]
    pairs = trajectory_to_examples(records)
    assert len(pairs) == 1
    assert set(pairs[0]) == {"prompt", "chosen", "rejected"}
    assert "login" in pairs[0]["chosen"]
    assert json.loads(pairs[0]["rejected"]) == {"url": "http://t"}


def test_reject_record_becomes_preference_pair():
    records = [{"tool": "hydra_bruteforce", "proposed_arguments": {"target": "t"}, "verdict": "reject"}]
    pairs = trajectory_to_examples(records)
    assert len(pairs) == 1
    assert pairs[0]["chosen"].startswith("No")
    assert "hydra_bruteforce" in pairs[0]["rejected"]


def test_approve_record_produces_no_pair():
    records = [{"tool": "nuclei_scan", "proposed_arguments": {}, "verdict": "approve"}]
    assert trajectory_to_examples(records) == []


# ── build_dataset ──


def test_build_dataset_messages_uses_findings_and_techniques(make_finding):
    t = Technique(id="t1", name="n", description="d", platform="web", engagement_id="e", date="2026-06-01")
    ds = build_dataset([make_finding()], [t], [], fmt="messages")
    assert len(ds) == 2
    assert all("messages" in ex for ex in ds)


def test_build_dataset_preference_uses_only_trajectories(make_finding):
    records = [{"tool": "x", "proposed_arguments": {}, "verdict": "reject"}]
    ds = build_dataset([make_finding()], [], records, fmt="preference")
    assert len(ds) == 1
    assert set(ds[0]) == {"prompt", "chosen", "rejected"}


# ── end-to-end through the stores ──


def test_flag_finding_to_messages_example(make_finding):
    f = make_finding(
        title="picoCTF flag captured: picoCTF{test_flag}",
        vuln_type="Sensitive Data Exposure",
        technique_used="shell",
        tags=["flag", "auto-ingested"],
    )
    ex = finding_to_example(f, fmt="messages")
    completion = json.loads(ex["messages"][2]["content"])
    assert completion["vuln_type"] == "Sensitive Data Exposure"
    assert "picoCTF" in completion["title"]


def test_flag_finding_to_sft_example(make_finding):
    f = make_finding(
        title="Secret/flag captured: picoCTF{an0th3r_fl4g}",
        vuln_type="Sensitive Data Exposure",
        technique_used="shell",
        tags=["flag", "auto-ingested"],
    )
    ex = finding_to_example(f, fmt="sft")
    assert set(ex) == {"prompt", "completion"}
    completion = json.loads(ex["completion"])
    assert completion["vuln_type"] == "Sensitive Data Exposure"


def test_export_roundtrip_via_stores(tmp_memory, tmp_engagements, make_finding):
    tmp_memory.add_finding(make_finding(id="f1", engagement_id="e1"))
    eng_id = "e1"
    tmp_engagements.append_trajectory(eng_id, {
        "tool": "sqlmap_scan", "proposed_arguments": {"url": "u"},
        "verdict": "edit", "final_arguments": {"url": "u?id=1"},
    })
    findings = tmp_memory.export_all_findings()
    trajectories = tmp_engagements.all_trajectories()
    assert len(findings) == 1
    assert len(trajectories) == 1
    prefs = build_dataset(findings, [], trajectories, fmt="preference")
    assert len(prefs) == 1
