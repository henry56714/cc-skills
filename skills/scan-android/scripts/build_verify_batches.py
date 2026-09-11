#!/usr/bin/env python3
"""Build lossless verifier batches from engine and AI-hunter candidate files."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from lib_scan import expand_cli_glob, resolve_repo_path


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
        raw_input = path.read_bytes()
        obj = json.loads(raw_input)
        found = _candidates(obj, path)
        try:
            display = path.relative_to(repo).as_posix()
        except ValueError:
            display = str(path)
        enriched = [
            _enrich_candidate(_validate_candidate(repo, candidate, path, index), display, index)
            for index, candidate in enumerate(found)
        ]
        all_candidates.extend(enriched)
        source_counts.append({
            "file": display,
            "candidates": len(found),
            "sha256": hashlib.sha256(raw_input).hexdigest(),
        })

    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("verify_batch_*.json"):
        stale.unlink()
    for stale in out_dir.glob("verified_batch_*.json"):
        stale.unlink()
    merge_receipt = out_dir / "merge_receipt.json"
    if merge_receipt.exists():
        merge_receipt.unlink()

    # 先按同规则/同定位聚拢，避免双样本重复刚好被批次边界拆开。
    groups: dict[tuple, list[dict]] = {}
    for cand in all_candidates:
        hint = cand.get("root_cause_hint")
        if isinstance(hint, dict) and all(
            isinstance(hint.get(field), str) and hint.get(field).strip()
            for field in ("primary_file", "symbol", "failure_mode")
        ):
            key = (
                "root-hint", hint["primary_file"], hint["symbol"], hint["failure_mode"],
            )
        else:
            key = (
                "location", cand.get("rule_id", ""), cand.get("file", ""),
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
    batch_receipts: list[dict] = []
    written = 0
    for index, batch in enumerate(batches):
        path = out_dir / f"verify_batch_{index}.json"
        path.write_text(json.dumps(batch, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        batch_files.append(str(path))
        batch_receipts.append({
            "file": str(path),
            "candidates": len(batch),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
        written += len(batch)

    result = {
        "schema_version": 2,
        "coverage_ok": (
            written == len(all_candidates)
            and len({c["candidate_id"] for c in all_candidates}) == len(all_candidates)
        ),
        "candidates_input": len(all_candidates),
        "candidates_batched": written,
        "batches": len(batches),
        "max_candidates": max_candidates,
        "token_budget": token_budget,
        "inputs": source_counts,
        "candidate_ids_unique": len({c["candidate_id"] for c in all_candidates}),
        "batch_files": batch_files,
        "batch_receipts": batch_receipts,
    }
    (out_dir / "verify_coverage.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result


_HUNT_RESULT_RE = re.compile(r"hunt_result_(\d+)_(\d+)\.json$")
_GAP_RESULT_RE = re.compile(r"hunt_gap_result_(\d+)\.json$")


def _normalize_repo_file(repo: Path, value: object, label: str, *, must_exist: bool) -> str:
    """Return a canonical repo-relative path or reject untrusted candidate data."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} 必须是非空仓库相对路径")
    candidate = Path(value.strip().replace("\\", "/"))
    if candidate.is_absolute():
        raise ValueError(f"{label} 不得是绝对路径: {value}")
    resolved = (repo / candidate).resolve()
    try:
        rel = resolved.relative_to(repo.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"{label} 越出仓库: {value}") from exc
    if must_exist and not resolved.is_file():
        raise ValueError(f"{label} 文件不存在或不可读: {rel}")
    return rel


def _validate_candidate(repo: Path, candidate: dict, source: Path, index: int) -> dict:
    """Validate every model/engine supplied location before it reaches verifier prompts."""
    item = dict(candidate)
    prefix = f"{source} candidates[{index}]"
    item["file"] = _normalize_repo_file(repo, item.get("file"), f"{prefix}.file", must_exist=True)

    line = item.get("line", 0)
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise ValueError(f"{prefix}.line 必须是从 1 开始的整数")
    line_count = 0
    try:
        with (repo / item["file"]).open("rb") as stream:
            last = b""
            while chunk := stream.read(64 * 1024):
                line_count += chunk.count(b"\n")
                last = chunk[-1:]
        if (repo / item["file"]).stat().st_size and last != b"\n":
            line_count += 1
    except OSError as exc:
        raise ValueError(f"{prefix}.file 无法读取: {item['file']}") from exc
    if line > line_count:
        raise ValueError(f"{prefix}.line 超出文件行数: {line} > {line_count}")

    end_line = item.get("end_line")
    if end_line is not None:
        if isinstance(end_line, bool) or not isinstance(end_line, int) or end_line < line:
            raise ValueError(f"{prefix}.end_line 必须是不小于 line 的整数")
        if end_line > line_count:
            raise ValueError(f"{prefix}.end_line 超出文件行数: {end_line} > {line_count}")

    hint = item.get("root_cause_hint")
    if isinstance(hint, dict) and "primary_file" in hint:
        hint = dict(hint)
        hint["primary_file"] = _normalize_repo_file(
            repo, hint["primary_file"], f"{prefix}.root_cause_hint.primary_file", must_exist=True,
        )
        item["root_cause_hint"] = hint

    for field in ("dataflow_path", "origin_trace", "related_locations"):
        hops = item.get(field)
        if hops is None:
            continue
        if not isinstance(hops, list):
            raise ValueError(f"{prefix}.{field} 必须是数组")
        normalized_hops: list[object] = []
        for hop_index, hop in enumerate(hops):
            if not isinstance(hop, dict):
                raise ValueError(f"{prefix}.{field}[{hop_index}] 必须是对象")
            normalized = dict(hop)
            if "file" in normalized:
                normalized["file"] = _normalize_repo_file(
                    repo,
                    normalized["file"],
                    f"{prefix}.{field}[{hop_index}].file",
                    must_exist=True,
                )
            normalized_hops.append(normalized)
        item[field] = normalized_hops
    return item


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
    elif gap_match := _GAP_RESULT_RE.search(Path(source_file).name):
        source_kind = "ai_gap_auditor"
        item.setdefault("engine", "ai-gap-audit")
        provenance = {
            "source_file": source_file,
            "source_kind": source_kind,
            "hunter_batch": int(gap_match.group(1)),
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
        try:
            inputs.append(resolve_repo_path(repo, raw, label="candidate input"))
        except ValueError as exc:
            print(json.dumps({"coverage_ok": False, "error": str(exc)}, ensure_ascii=False))
            return 1
    for pattern in args.input_glob:
        try:
            matches = expand_cli_glob(repo, pattern, label="candidate input glob")
            inputs.extend(
                resolve_repo_path(repo, match, label="candidate input glob result")
                for match in matches
            )
        except ValueError as exc:
            print(json.dumps({"coverage_ok": False, "error": str(exc)}, ensure_ascii=False))
            return 1
    # Dedup while preserving deterministic order.
    inputs = list(dict.fromkeys(p.resolve() for p in inputs))
    missing = [str(p) for p in inputs if not p.is_file()]
    if not inputs or missing:
        print(json.dumps({"coverage_ok": False, "error": "候选输入缺失", "missing": missing}, ensure_ascii=False))
        return 1
    if args.max_candidates < 1 or args.token_budget < 1000:
        print(json.dumps({"coverage_ok": False, "error": "批次参数无效"}, ensure_ascii=False))
        return 1
    try:
        out_dir = resolve_repo_path(repo, args.out_dir, label="verifier output directory")
        result = build(repo, inputs, out_dir, args.max_candidates, args.token_budget)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"coverage_ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["coverage_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
