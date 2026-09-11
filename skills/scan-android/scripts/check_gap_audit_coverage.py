#!/usr/bin/env python3
"""Mechanically validate the independent Hunter false-negative audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_gap_audit_batches import construct_expected_plan  # noqa: E402
from check_hunt_coverage import _load_json, _validate_file_reads  # noqa: E402
from lib_scan import resolve_cli_path, resolve_repo_path, strict_json_equal  # noqa: E402


_RESULT_RE = re.compile(r"hunt_gap_result_(\d+)\.json$")
_DISPOSITIONS = {"agree_no_signal", "agree_mitigated", "new_candidate", "unresolved"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_case_audits(
    obj: dict,
    expected_cases: set[str],
    expected_files: set[str],
    repo: Path,
) -> list[str]:
    audits = obj.get("case_audits")
    if not isinstance(audits, list):
        return ["缺 case_audits 数组"]
    problems: list[str] = []
    by_case: dict[str, dict] = {}
    for audit in audits:
        if not isinstance(audit, dict) or not isinstance(audit.get("case_id"), str):
            problems.append("case_audits 含无效记录")
            continue
        case_id = audit["case_id"]
        if case_id in by_case:
            problems.append(f"重复 case 审计: {case_id}")
        by_case[case_id] = audit
    missing = expected_cases - set(by_case)
    if missing:
        problems.append("漏审 case: " + ", ".join(sorted(missing)))
    extra = set(by_case) - expected_cases
    if extra:
        problems.append("计划外 case: " + ", ".join(sorted(extra)))
    candidates = obj.get("candidates", [])
    if not isinstance(candidates, list):
        candidates = []
    candidate_rules = {
        candidate.get("rule_id") for candidate in candidates
        if isinstance(candidate, dict) and isinstance(candidate.get("rule_id"), str)
    }
    for case_id in sorted(expected_cases & set(by_case)):
        audit = by_case[case_id]
        disposition = audit.get("disposition")
        if disposition not in _DISPOSITIONS:
            problems.append(f"{case_id} disposition 无效")
            continue
        signals = audit.get("signals_checked")
        if not isinstance(signals, list) or not signals or not all(
            isinstance(value, str) and value.strip() for value in signals
        ):
            problems.append(f"{case_id} 缺 signals_checked")
        conclusion = audit.get("conclusion")
        if not isinstance(conclusion, str) or len(conclusion.strip()) < 4:
            problems.append(f"{case_id} 缺有效 conclusion")
        evidence = audit.get("evidence", [])
        if not isinstance(evidence, list):
            problems.append(f"{case_id} evidence 必须是数组")
            evidence = []
        if disposition in {"agree_mitigated", "new_candidate"} and not evidence:
            problems.append(f"{case_id} 的 {disposition} 缺源码证据")
        for location in evidence:
            if not isinstance(location, dict):
                problems.append(f"{case_id} evidence 含无效记录")
                continue
            rel = location.get("file")
            if not isinstance(rel, str) or rel.replace("\\", "/") not in expected_files:
                problems.append(f"{case_id} evidence 指向批外文件")
            line = location.get("line")
            if isinstance(line, bool) or not isinstance(line, int) or line < 1:
                problems.append(f"{case_id} evidence 缺有效行号")
            elif isinstance(rel, str) and rel.replace("\\", "/") in expected_files:
                try:
                    source_path = resolve_repo_path(
                        repo, rel.replace("\\", "/"),
                        label=f"{case_id} evidence.file",
                    )
                    line_count = len(
                        source_path.read_text(
                            encoding="utf-8", errors="replace"
                        ).splitlines()
                    )
                except OSError:
                    line_count = 0
                except ValueError:
                    problems.append(f"{case_id} evidence 文件越出仓库")
                    continue
                if line > line_count:
                    problems.append(f"{case_id} evidence 行号超出文件范围")
        if disposition == "new_candidate" and case_id not in candidate_rules:
            problems.append(f"{case_id} 标为 new_candidate，但 candidates 无对应 rule_id")
        if disposition == "unresolved":
            problems.append(f"{case_id} 审计仍 unresolved，不能宣称完整")
    return problems


def check(
    repo: Path, out_dir: Path, plan_path: Path, *, write_output: bool = True,
) -> dict:
    provided_plan = _load_json(plan_path)
    if not isinstance(provided_plan, dict) or provided_plan.get("coverage_ok") is not True:
        return {"ok": False, "error": "gap_audit_plan 无效或 coverage_ok=false"}
    if type(provided_plan.get("schema_version")) is not int or (
        provided_plan.get("schema_version") != 2
    ):
        return {"ok": False, "error": "当前完整性闸要求 gap_audit_plan schema_version=2"}
    plan_integrity_problems: list[str] = []
    try:
        plan, _ = construct_expected_plan(repo, out_dir)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"无法从 Hunter 产物重建漏报审计计划: {exc}"}
    if not strict_json_equal(provided_plan, plan):
        plan_integrity_problems.append(
            "gap_audit_plan 与当前 Hunter 批次/结果的确定性重建不一致"
        )
    details = plan.get("batches_detail")
    if not isinstance(details, list):
        return {"ok": False, "error": "gap_audit_plan 缺 batches_detail"}

    expected: dict[int, dict] = {}
    for detail in details:
        if not isinstance(detail, dict) or type(detail.get("batch")) is not int:
            return {"ok": False, "error": "gap_audit_plan 批次无效"}
        batch = detail["batch"]
        if batch in expected:
            return {"ok": False, "error": f"gap_audit_plan 重复批次: {batch}"}
        expected[batch] = detail
    if plan.get("batches") != len(details):
        return {"ok": False, "error": "gap_audit_plan 批次数与明细不一致"}

    for label, path_field, hash_field in (
        ("Hunter plan", "source_hunt_plan", "source_hunt_plan_sha256"),
        ("Hunter coverage", "source_hunter_coverage", "source_hunter_coverage_sha256"),
    ):
        try:
            source_path = resolve_repo_path(
                repo, str(plan.get(path_field, "")), label=f"gap plan {path_field}",
            )
            if _sha256(source_path) != plan.get(hash_field):
                plan_integrity_problems.append(
                    f"{label} 在漏报审计计划生成后发生变化"
                )
        except (OSError, ValueError):
            plan_integrity_problems.append(f"{label} 不可读或越出仓库")
    for batch, detail in expected.items():
        for label, path, field in (
            ("source batch", out_dir / f"hunt_batch_{batch}.json", "source_batch_sha256"),
            ("prior results", out_dir / f"gap_prior_{batch}.json", "prior_results_sha256"),
            ("audit input", out_dir / f"gap_audit_batch_{batch}.json", "audit_input_sha256"),
        ):
            try:
                if _sha256(path) != detail.get(field):
                    plan_integrity_problems.append(f"batch {batch} {label} 在计划生成后发生变化")
            except OSError:
                plan_integrity_problems.append(f"batch {batch} {label} 不可读")

    result_paths = sorted(out_dir.glob("hunt_gap_result_*.json"))
    seen: set[int] = set()
    batches: list[dict] = []
    stray: list[str] = []
    for path in result_paths:
        match = _RESULT_RE.fullmatch(path.name)
        obj = _load_json(path)
        if not match or not isinstance(obj, dict) or "__error__" in obj:
            stray.append(path.name)
            continue
        batch = int(match.group(1))
        if (
            batch not in expected
            or type(obj.get("batch")) is not int
            or obj.get("batch") != batch
            or batch in seen
        ):
            stray.append(path.name)
            continue
        seen.add(batch)
        detail = expected[batch]
        expected_files = set(detail.get("files", []))
        expected_cases = set(detail.get("expected_case_ids", []))
        expected_perspectives = set(detail.get("expected_perspectives", []))
        problems: list[str] = []
        if obj.get("independent_pass") is not True:
            problems.append("未声明先独立审计")
        if obj.get("prior_results_compared_after_pass") is not True:
            problems.append("未声明独立判断后再对照 Hunter 结论")
        audited_perspectives = obj.get("perspectives_audited")
        if not isinstance(audited_perspectives, list) or not all(
            isinstance(value, str) for value in audited_perspectives
        ):
            problems.append("perspectives_audited 必须是字符串数组")
        elif set(audited_perspectives) != expected_perspectives:
            problems.append("漏报审计视角与计划不一致")
        candidates = obj.get("candidates")
        if not isinstance(candidates, list) or not all(isinstance(x, dict) for x in candidates):
            problems.append("candidates 必须是对象数组")
        problems.extend(_validate_file_reads(obj.get("files_reviewed"), expected_files, repo))
        problems.extend(_validate_case_audits(obj, expected_cases, expected_files, repo))
        batches.append({
            "batch": batch,
            "ok": not problems,
            "problems": problems,
            "cases_expected": len(expected_cases),
            "candidates": len(candidates) if isinstance(candidates, list) else 0,
        })

    missing = sorted(set(expected) - seen)
    for batch in missing:
        batches.append({
            "batch": batch, "ok": False,
            "problems": ["缺独立漏报审计结果"],
            "cases_expected": len(expected[batch].get("expected_case_ids", [])),
            "candidates": 0,
        })
    batches.sort(key=lambda item: item["batch"])
    result = {
        "schema_version": 1,
        "ok": (
            bool(expected) and not missing and not stray and not plan_integrity_problems
            and all(item["ok"] for item in batches)
        ),
        "batches_total": len(expected),
        "batches": batches,
        "missing_batches": missing,
        "stray_or_invalid_results": stray,
        "plan_integrity_problems": plan_integrity_problems,
        "candidates_total": sum(item["candidates"] for item in batches),
    }
    if write_output:
        (out_dir / "gap_audit_coverage.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=".scan/tmp")
    parser.add_argument("--plan", default=None)
    args = parser.parse_args()
    repo = Path(args.repo_root).resolve()
    try:
        out_dir = resolve_cli_path(repo, args.out_dir, label="gap audit output directory")
        plan_path = (
            resolve_cli_path(repo, args.plan, label="gap audit plan")
            if args.plan else out_dir / "gap_audit_plan.json"
        )
        result = check(repo, out_dir, plan_path)
    except ValueError as exc:
        result = {"ok": False, "error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    sys.exit(main())
