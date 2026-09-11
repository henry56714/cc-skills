#!/usr/bin/env python3
"""Build independent false-negative audit inputs from completed hunter results."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib_scan import resolve_cli_path  # noqa: E402


_RESULT_RE = re.compile(r"hunt_result_(\d+)_(\d+)\.json$")
_LOGIC_CASES = {f"R-AI-{number:03d}" for number in range(67, 73)}


def _load_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"无法读取 JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON 顶层必须是对象: {path}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _repo_rel(repo: Path, path: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def _json_text(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _object_sha256(value: dict) -> str:
    return hashlib.sha256(_json_text(value).encode("utf-8")).hexdigest()


def _construct_batch(
    repo: Path, out_dir: Path, detail: dict,
) -> tuple[dict, dict, dict]:
    if not isinstance(detail, dict) or type(detail.get("batch")) is not int:
        raise ValueError("batches_detail 含无效批次")
    batch = detail["batch"]
    batch_path = out_dir / f"hunt_batch_{batch}.json"
    batch_obj = _load_object(batch_path)
    expected_cases = detail.get("expected_case_ids", [])
    expected_perspectives = detail.get("expected_perspectives", [])
    if not isinstance(expected_cases, list) or not all(isinstance(x, str) for x in expected_cases):
        raise ValueError(f"batch {batch} expected_case_ids 无效")
    if not isinstance(expected_perspectives, list) or not all(
        isinstance(x, str) for x in expected_perspectives
    ):
        raise ValueError(f"batch {batch} expected_perspectives 无效")
    batch_files = [
        item.get("file") for item in batch_obj.get("files", []) if isinstance(item, dict)
    ]
    if (
        batch_obj.get("batch") != batch
        or batch_obj.get("expected_case_ids", []) != expected_cases
        or batch_obj.get("expected_perspectives", []) != expected_perspectives
        or batch_files != detail.get("files", [])
    ):
        raise ValueError(f"batch {batch} 与 hunt_coverage 记录不一致；请重建并重跑 Hunter coverage")

    prior_results: list[dict] = []
    statuses: dict[str, set[str]] = {case: set() for case in expected_cases}
    for result_path in sorted(out_dir.glob(f"hunt_result_{batch}_*.json")):
        match = _RESULT_RE.fullmatch(result_path.name)
        result = _load_object(result_path)
        if (
            not match
            or result.get("batch") != batch
            or type(result.get("sample")) is not int
            or int(match.group(1)) != batch
            or int(match.group(2)) != result.get("sample")
        ):
            raise ValueError(f"Hunter 结果命名或 batch/sample 不一致: {result_path}")
        assessments = result.get("case_assessments")
        candidates = result.get("candidates")
        if expected_cases and not isinstance(assessments, list):
            raise ValueError(f"Hunter 结果缺 case_assessments: {result_path}")
        if not isinstance(candidates, list) or not all(
            isinstance(candidate, dict) for candidate in candidates
        ):
            raise ValueError(f"Hunter 结果 candidates 无效: {result_path}")
        compact_assessments: list[dict] = []
        for assessment in assessments or []:
            if not isinstance(assessment, dict):
                continue
            case_id = assessment.get("case_id")
            status = assessment.get("status")
            if isinstance(case_id, str) and isinstance(status, str):
                statuses.setdefault(case_id, set()).add(status)
            compact_assessments.append({
                key: assessment.get(key)
                for key in ("case_id", "status", "signals_checked", "evidence", "conclusion")
            })
        prior_results.append({
            "result_file": _repo_rel(repo, result_path),
            "sample": result["sample"],
            "case_assessments": compact_assessments,
            "candidate_locations": [
                {
                    "rule_id": candidate.get("rule_id"),
                    "file": candidate.get("file"),
                    "line": candidate.get("line"),
                }
                for candidate in candidates
            ],
        })
    if not prior_results:
        raise ValueError(f"batch {batch} 没有 Hunter 结果")

    negative_cases = sorted(
        case for case in expected_cases
        if statuses.get(case, set()) <= {"no_signal", "mitigated"}
    )
    disagreements = sorted(
        case for case, values in statuses.items() if len(values) > 1
    )
    prior_path = out_dir / f"gap_prior_{batch}.json"
    prior_obj = {
        "schema_version": 1,
        "batch": batch,
        "audit_focus": {
            "negative_or_mitigated_cases": negative_cases,
            "cross_sample_disagreements": disagreements,
            "business_logic_cases": sorted(_LOGIC_CASES & set(expected_cases)),
        },
        "prior_hunter_results": prior_results,
    }
    audit_path = out_dir / f"gap_audit_batch_{batch}.json"
    audit_obj = {
        "schema_version": 1,
        "batch": batch,
        "source_batch_file": _repo_rel(repo, batch_path),
        "repo_map_file": _repo_rel(repo, out_dir / f"repo_map_{batch}.md"),
        "files": batch_obj.get("files", []),
        "expected_perspectives": expected_perspectives,
        "expected_case_ids": expected_cases,
        "prior_hunter_results_file": _repo_rel(repo, prior_path),
        "context_scope_path": batch_obj.get("context_scope_path"),
        "instructions": (
            "先独立通读源码并形成判断，再读取 prior_hunter_results_file 挑战其 no_signal/mitigated；"
            "新发现必须输出 candidate，不能因前一轮未报而从众。"
        ),
    }
    plan_detail = {
        "batch": batch,
        "input": _repo_rel(repo, audit_path),
        "files": batch_files,
        "expected_case_ids": expected_cases,
        "expected_perspectives": expected_perspectives,
        "negative_cases": negative_cases,
        "disagreements": disagreements,
        "source_batch_sha256": _sha256(batch_path),
        "prior_results_sha256": _object_sha256(prior_obj),
        "audit_input_sha256": _object_sha256(audit_obj),
    }
    return plan_detail, prior_obj, audit_obj


def construct_expected_plan(repo: Path, out_dir: Path) -> tuple[dict, dict[str, dict]]:
    """Rebuild the canonical plan and generated inputs without mutating disk."""
    coverage_path = out_dir / "hunt_coverage.json"
    hunter_check_path = out_dir / "hunt_perspective_coverage.json"
    coverage = _load_object(coverage_path)
    hunter_check = _load_object(hunter_check_path)
    if type(coverage.get("schema_version")) is not int or (
        coverage.get("schema_version") != 3 or coverage.get("coverage_ok") is not True
    ):
        raise ValueError("hunt_coverage.json 未通过，不能建立漏报审计")
    if type(hunter_check.get("schema_version")) is not int or (
        hunter_check.get("schema_version") != 3 or hunter_check.get("ok") is not True
    ):
        raise ValueError("hunt_perspective_coverage.json 未通过，不能建立漏报审计")

    details = coverage.get("batches_detail")
    if not isinstance(details, list):
        raise ValueError("hunt_coverage.json 缺 batches_detail")

    artifacts: dict[str, dict] = {}
    plan_batches: list[dict] = []
    seen_batches: set[int] = set()
    for detail in details:
        plan_detail, prior_obj, audit_obj = _construct_batch(repo, out_dir, detail)
        batch = plan_detail["batch"]
        if batch in seen_batches:
            raise ValueError(f"hunt_coverage.json 重复批次: {batch}")
        seen_batches.add(batch)
        plan_batches.append(plan_detail)
        artifacts[f"gap_prior_{batch}.json"] = prior_obj
        artifacts[f"gap_audit_batch_{batch}.json"] = audit_obj

    plan = {
        "schema_version": 2,
        "coverage_ok": len(plan_batches) == len(details),
        "batches": len(plan_batches),
        "source_hunt_plan": _repo_rel(repo, coverage_path),
        "source_hunt_plan_sha256": _sha256(coverage_path),
        "source_hunter_coverage": _repo_rel(repo, hunter_check_path),
        "source_hunter_coverage_sha256": _sha256(hunter_check_path),
        "batches_detail": plan_batches,
    }
    return plan, artifacts


def build(repo: Path, out_dir: Path) -> dict:
    plan, artifacts = construct_expected_plan(repo, out_dir)
    for pattern in (
        "gap_audit_batch_*.json", "gap_prior_*.json", "hunt_gap_result_*.json",
        "verify_batch_*.json", "verified_batch_*.json",
    ):
        for stale in out_dir.glob(pattern):
            stale.unlink()
    for name in ("gap_audit_plan.json", "gap_audit_coverage.json", "verify_coverage.json", "merge_receipt.json"):
        stale = out_dir / name
        if stale.exists():
            stale.unlink()

    for name, value in artifacts.items():
        (out_dir / name).write_text(_json_text(value), encoding="utf-8")
    (out_dir / "gap_audit_plan.json").write_text(_json_text(plan), encoding="utf-8")
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=".scan/tmp")
    args = parser.parse_args()
    repo = Path(args.repo_root).resolve()
    try:
        out_dir = resolve_cli_path(repo, args.out_dir, label="gap audit output directory")
        result = build(repo, out_dir)
    except (OSError, ValueError) as exc:
        print(json.dumps({"coverage_ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["coverage_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
