"""Turn saved engagement data into fine-tuning datasets.

Three sources become training examples:
  * Findings   -> "write a finding from this observation" supervised examples.
  * Techniques -> "explain this technique" supervised examples.
  * HITL trajectories -> preference pairs. Every human approve/reject/edit during
    the collaboration phase is captured (see EngagementManager.append_trajectory);
    an EDIT yields (chosen = human-corrected args, rejected = model's proposal), a
    REJECT yields (chosen = decline/reconsider, rejected = the proposed call).
    This is the payoff of the human-in-the-loop design: supervision becomes labels.

Pure functions only — no I/O, no DB. scripts/export_training_data.py wires them
to MemoryStore + EngagementManager and writes JSONL. Formats:
  messages    - chat SFT: {"messages": [system, user, assistant]}
  sft         - {"prompt", "completion"}
  preference  - {"prompt", "chosen", "rejected"} (trajectory-derived)
"""
from __future__ import annotations

import json
from typing import Any

from memory.schemas import Finding, Technique

FINDING_SYSTEM = (
    "You are Thaghrawy, an autonomous penetration-testing assistant. Given an "
    "observation from a security tool, write a concise, evidence-backed finding."
)
TECHNIQUE_SYSTEM = (
    "You are Thaghrawy, a penetration-testing assistant with cross-engagement "
    "memory. Explain the requested technique precisely."
)


def _dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def _pair(prompt: str, completion: str, system: str, fmt: str) -> dict[str, Any]:
    if fmt == "messages":
        return {"messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": completion},
        ]}
    return {"prompt": prompt, "completion": completion}


def finding_to_example(finding: Finding, fmt: str = "messages") -> dict[str, Any]:
    lines = [f"Target: {finding.target}"]
    if finding.affected_component:
        lines.append(f"Affected component: {finding.affected_component}")
    lines.append(f"Technique: {finding.technique_used}")
    lines.append(f"Observation: {finding.description}")
    lines.append("Write the finding as JSON (title, severity, vuln_type, "
                 "reproduction_steps, business_impact, remediation).")
    prompt = "\n".join(lines)
    completion = _dumps({
        "title": finding.title,
        "severity": finding.severity,
        "vuln_type": finding.vuln_type,
        "reproduction_steps": finding.reproduction_steps,
        "business_impact": finding.business_impact or "",
        "remediation": finding.remediation or "",
    })
    return _pair(prompt, completion, FINDING_SYSTEM, fmt)


def technique_to_example(technique: Technique, fmt: str = "messages") -> dict[str, Any]:
    prompt = (
        f"Explain the penetration-testing technique '{technique.name}' — what it "
        "does and what it works against."
    )
    completion = _dumps({
        "name": technique.name,
        "description": technique.description,
        "works_against": technique.works_against,
        "platform": technique.platform,
    })
    return _pair(prompt, completion, TECHNIQUE_SYSTEM, fmt)


def trajectory_to_examples(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Preference pairs from human verdicts on proposed tool calls."""
    pairs: list[dict[str, Any]] = []
    for r in records:
        tool = r.get("tool", "unknown_tool")
        proposed = r.get("proposed_arguments")
        verdict = r.get("verdict")
        if verdict == "edit":
            pairs.append({
                "prompt": f"Choose the arguments for the `{tool}` tool in this pentest step.",
                "chosen": _dumps(r.get("final_arguments")),
                "rejected": _dumps(proposed),
            })
        elif verdict == "reject":
            pairs.append({
                "prompt": f"Should we run `{tool}` with arguments {_dumps(proposed)}?",
                "chosen": "No — the operator declined this call. Reconsider and "
                          "propose a more relevant or safer action.",
                "rejected": f"Run `{tool}` with {_dumps(proposed)}.",
            })
    return pairs


def build_dataset(
    findings: list[Finding],
    techniques: list[Technique],
    trajectories: list[dict[str, Any]],
    fmt: str = "messages",
) -> list[dict[str, Any]]:
    """Assemble the full dataset for the requested format."""
    if fmt == "preference":
        return trajectory_to_examples(trajectories)
    examples = [finding_to_example(f, fmt) for f in findings]
    examples += [technique_to_example(t, fmt) for t in techniques]
    return examples
