# Training-data export

Every engagement produces data we can use to fine-tune / improve our own model.
This package turns that saved data into fine-tuning-ready JSONL.

## Sources

| Source | Where it lives | Becomes |
|---|---|---|
| **Findings** | ChromaDB (`MemoryStore.export_all_findings`) | "write a finding from this observation" supervised examples |
| **Techniques** | ChromaDB (`MemoryStore.export_all_techniques`) | "explain this technique" supervised examples |
| **HITL trajectories** | `engagements/sessions/<id>.trajectory.jsonl` (`EngagementManager.append_trajectory`) | **preference pairs** from human approve/reject/edit verdicts |

The trajectory file is written during the **collaboration** phase: each time the
operator approves, rejects, or edits a proposed tool call, a record is appended
(`proposed_arguments`, `verdict`, `final_arguments`, `rejected`, trimmed
`result`). This is the payoff of the human-in-the-loop design — human supervision
becomes labeled training data.

## Formats

- `messages` (default) — chat SFT: `{"messages": [system, user, assistant]}`.
  Portable across OpenAI/Anthropic-style supervised fine-tuning.
- `sft` — flat `{"prompt", "completion"}` pairs.
- `preference` — `{"prompt", "chosen", "rejected"}` from trajectory verdicts, for
  DPO-style preference tuning. An **edit** → chosen = the human-corrected
  arguments, rejected = the model's original; a **reject** → chosen = decline /
  reconsider, rejected = the proposed call.

## Usage

```bash
# CLI
python -m scripts.export_training_data --format messages   --out data/train.jsonl
python -m scripts.export_training_data --format preference --out data/prefs.jsonl

# HTTP
GET /api/training/export?format=messages
```

## Notes

- `preference` only draws from trajectories; `messages`/`sft` draw from
  findings + techniques. Run engagements (and curate findings) to populate them.
- No raw credentials are written to trajectories (per the project security rules);
  tool results are truncated before capture.
