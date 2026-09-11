#!/usr/bin/env python3
"""Create a lossless needs-review result when one verifier batch fails."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from lib_scan import resolve_cli_path


def build_fallback(batch_path: Path, reason: str, language: str = "zh") -> dict:
    values = json.loads(batch_path.read_text(encoding="utf-8"))
    if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
        raise ValueError("verifier input batch must be an array of objects")
    match = re.fullmatch(r"verify_batch_(\d+)\.json", batch_path.name)
    if not match:
        raise ValueError("input filename must be verify_batch_N.json")
    review: list[dict] = []
    for index, item in enumerate(values):
        file = str(item.get("file", ""))
        line = int(item.get("line", 0) or 0)
        candidate_id = str(item.get("candidate_id", f"missing-candidate-id-{index}"))
        hint = item.get("root_cause_hint")
        root = hint if isinstance(hint, dict) and all(
            isinstance(hint.get(field), str) and hint.get(field).strip()
            for field in ("primary_file", "symbol", "failure_mode")
        ) else {
            "primary_file": file or "unknown",
            "symbol": f"line-{line}",
            "failure_mode": "verifier-failed-unresolved",
        }
        zh = language == "zh"
        review.append({
            "file": file,
            "line": line,
            "rule_id": str(item.get("rule_id", "R-UNKNOWN")),
            "category": str(item.get("category", "review/verifier-failed")),
            "severity": str(item.get("severity", "info")),
            "title": "验证器失败，候选保留待复核" if zh else "Verifier failed; candidate retained",
            "evidence": str(item.get("snippet") or item.get("message") or "candidate retained"),
            "why": str(item.get("why") or item.get("message") or reason),
            "repro": "恢复验证器后重新验证该候选。" if zh else "Retry this candidate after restoring the verifier.",
            "suggestion": "不要将此项解释为假阳性；修复验证失败后重新取证。" if zh else "Do not treat this as a false positive; re-run evidence collection.",
            "root_cause": root,
            "source_candidate_ids": [candidate_id],
            "provenance": item.get("provenance", []),
            "review_reason": reason,
            "missing_evidence": ["independent verifier adjudication"],
        })
    return {
        "batch": int(match.group(1)),
        "candidates_input": len(values),
        "candidates_adjudicated": len(values),
        "false_positive_count": 0,
        "false_positive_ids": [],
        "duplicates_merged_count": 0,
        "confirmed": [],
        "needs_review": review,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--language", choices=("zh", "en"), default="zh")
    args = parser.parse_args()
    try:
        repo = Path.cwd().resolve()
        input_path = resolve_cli_path(repo, args.input, label="fallback verifier input")
        output = resolve_cli_path(repo, args.output, label="fallback verifier output")
        result = build_fallback(input_path, args.reason, args.language)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
