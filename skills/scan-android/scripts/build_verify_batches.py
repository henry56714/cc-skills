#!/usr/bin/env python3
"""Build lossless verifier batches from engine and AI-hunter candidate files."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def _candidates(obj: object, source: Path) -> list[dict]:
    if isinstance(obj, list):
        values = obj
    elif isinstance(obj, dict) and isinstance(obj.get("candidates"), list):
        values = obj["candidates"]
    else:
        raise ValueError(f"输入不含 candidates 数组: {source}")
    if not all(isinstance(x, dict) for x in values):
        raise ValueError(f"候选必须都是 JSON 对象: {source}")
    return values


def build(
    repo: Path,
    inputs: list[Path],
    out_dir: Path,
    max_candidates: int = 20,
    token_budget: int = 30_000,
) -> dict:
    all_candidates: list[dict] = []
    source_counts: list[dict] = []
    for path in inputs:
        obj = json.loads(path.read_text(encoding="utf-8"))
        found = _candidates(obj, path)
        try:
            display = path.relative_to(repo).as_posix()
        except ValueError:
            display = str(path)
        enriched = [
            _enrich_candidate(candidate, display, index)
            for index, candidate in enumerate(found)
        ]
        all_candidates.extend(enriched)
        source_counts.append({"file": display, "candidates": len(found)})

    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("verify_batch_*.json"):
        stale.unlink()
    for stale in out_dir.glob("verified_batch_*.json"):
        stale.unlink()

    # 先按同规则/同定位聚拢，避免双样本重复刚好被批次边界拆开。
    groups: dict[tuple, list[dict]] = {}
    for cand in all_candidates:
        key = (
            cand.get("rule_id", ""), cand.get("file", ""),
            int(cand.get("line", 0) or 0),
        )
        groups.setdefault(key, []).append(cand)

    batches: list[list[dict]] = []
    current: list[dict] = []
    current_tokens = 0
    for group in groups.values():
        for start in range(0, len(group), max_candidates):
            chunk = group[start:start + max_candidates]
            estimate = sum(max(64, len(json.dumps(c, ensure_ascii=False)) // 3) for c in chunk)
            if current and (len(current) + len(chunk) > max_candidates or current_tokens + estimate > token_budget):
                batches.append(current)
                current = []
                current_tokens = 0
            current.extend(chunk)
            current_tokens += estimate
    if current:
        batches.append(current)
    if not batches:
        # A deterministic empty batch lets the workflow exercise the same
        # verifier/merge contract without a special no-candidate branch.
        batches.append([])

    batch_files: list[str] = []
    written = 0
    for index, batch in enumerate(batches):
        path = out_dir / f"verify_batch_{index}.json"
        path.write_text(json.dumps(batch, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        batch_files.append(str(path))
        written += len(batch)

    result = {
        "coverage_ok": written == len(all_candidates),
        "candidates_input": len(all_candidates),
        "candidates_batched": written,
        "batches": len(batches),
        "max_candidates": max_candidates,
        "token_budget": token_budget,
        "inputs": source_counts,
        "candidate_ids_unique": len({c["candidate_id"] for c in all_candidates}),
        "batch_files": batch_files,
    }
    (out_dir / "verify_coverage.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result


_HUNT_RESULT_RE = re.compile(r"hunt_result_(\d+)_(\d+)\.json$")


def _enrich_candidate(candidate: dict, source_file: str, index: int) -> dict:
    item = dict(candidate)
    match = _HUNT_RESULT_RE.search(Path(source_file).name)
    if match:
        source_kind = "ai_hunter"
        item.setdefault("engine", "ai")
        provenance = {
            "source_file": source_file,
            "source_kind": source_kind,
            "hunter_batch": int(match.group(1)),
            "hunter_sample": int(match.group(2)),
        }
    else:
        source_kind = "tool_engine"
        provenance = {
            "source_file": source_file,
            "source_kind": source_kind,
            "engine": item.get("engine", "unknown"),
        }
    raw = json.dumps(candidate, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    candidate_id = hashlib.sha256(f"{source_file}:{index}:{raw}".encode("utf-8")).hexdigest()[:24]
    item["candidate_id"] = candidate_id
    item["provenance"] = [provenance]
    return item


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--input", action="append", default=[], help="候选 JSON 文件，可重复")
    ap.add_argument("--input-glob", action="append", default=[], help="相对 repo 的候选文件 glob，可重复")
    ap.add_argument("--out-dir", default=".scan/tmp")
    ap.add_argument("--max-candidates", type=int, default=20)
    ap.add_argument("--token-budget", type=int, default=30_000)
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()
    inputs: list[Path] = []
    for raw in args.input:
        path = Path(raw)
        inputs.append(path if path.is_absolute() else repo / path)
    for pattern in args.input_glob:
        inputs.extend(sorted(repo.glob(pattern)))
    # Dedup while preserving deterministic order.
    inputs = list(dict.fromkeys(p.resolve() for p in inputs))
    missing = [str(p) for p in inputs if not p.is_file()]
    if not inputs or missing:
        print(json.dumps({"coverage_ok": False, "error": "候选输入缺失", "missing": missing}, ensure_ascii=False))
        return 1
    if args.max_candidates < 1 or args.token_budget < 1000:
        print(json.dumps({"coverage_ok": False, "error": "批次参数无效"}, ensure_ascii=False))
        return 1
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo / out_dir
    try:
        result = build(repo, inputs, out_dir, args.max_candidates, args.token_budget)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"coverage_ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["coverage_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
