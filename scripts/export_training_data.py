"""Export saved engagement data as a fine-tuning dataset (JSONL).

    python -m scripts.export_training_data --format messages --out data/train.jsonl
    python -m scripts.export_training_data --format preference --out data/prefs.jsonl

Sources: findings + techniques from ChromaDB (MemoryStore) and the human-decision
trajectories captured during collaboration (EngagementManager). See
training/exporter.py for the example schemas and training/README.md for details.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from engagements.manager import EngagementManager
from memory.store import MemoryStore
from training.exporter import build_dataset

_FORMATS = ("messages", "sft", "preference")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export training data as JSONL.")
    parser.add_argument("--format", choices=_FORMATS, default="messages")
    parser.add_argument("--out", default="data/train.jsonl", help="output JSONL path")
    args = parser.parse_args(argv)

    memory = MemoryStore()
    manager = EngagementManager()

    findings = memory.export_all_findings()
    techniques = memory.export_all_techniques()
    trajectories = manager.all_trajectories()
    dataset = build_dataset(findings, techniques, trajectories, fmt=args.format)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as fh:
        for example in dataset:
            fh.write(json.dumps(example, ensure_ascii=False) + "\n")

    print(
        f"Wrote {len(dataset)} example(s) [{args.format}] to {args.out}\n"
        f"  sources: {len(findings)} finding(s), {len(techniques)} technique(s), "
        f"{len(trajectories)} decision record(s)"
    )
    if not dataset:
        print("  (no data yet — run engagements and curate findings first)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
