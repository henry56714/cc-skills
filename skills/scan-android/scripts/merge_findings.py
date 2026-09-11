#!/usr/bin/env python3
"""
将 verifier 输出拆分写入 confirmed findings 与 needs-review（无状态，每次覆盖）。

v4 决定：去掉跨扫描状态机。本脚本**不**读取旧 findings、不维护 first/last_seen、
不做回归重开 / 关闭消失项——每次扫描独立，只输出本次确认的问题。
跨源/批次去重仅在本次输入内进行：优先按结构化 `root_cause` 合并同一修复点，
缺少根因信息的旧输入才回退到精确位置键。

用法:
    merge_findings.py [--findings PATH] [--needs-review PATH]

推荐从 stdin 读入对象；旧版裸数组仍按 confirmed 兼容：
    {"confirmed": [...], "needs_review": [...]}

每个 confirmed 元素为：
    {
      "file": "...", "line": 42, "end_line": 45,  (end_line 可选)
      "rule_id": "R-STB-007", "category": "stability/unnamed-thread",
      "severity": "minor", "title": "...", "evidence": "...",
      "why": "...", "repro": "...", "suggestion": "...",
      "dataflow_path": [...], "origin_trace": [...]  (均可选)
    }

取证闸（C）：条件触发型类别（static-context-leak / 主线程阻塞 / 越权数据流 等，见
_needs_origin）的 finding 必须带回溯源头链（非空 `dataflow_path` 或 `origin_trace`），
否则不会静默丢弃，而是转入 needs-review 并说明缺少的证据。

输出:
    stdout 一行 JSON 统计：
    {"findings_total": N, "needs_review_total": N, "findings_duplicate": N,
     "moved_to_review_no_origin": N}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from check_gap_audit_coverage import check as check_gap_audit_coverage  # noqa: E402
from check_hunt_coverage import check as check_hunt_coverage  # noqa: E402
from lib_scan import (
    atomic_write_json, current_skill_fingerprint, effective_excluded_engines,
    effective_hunt_policy, expand_cli_glob, finding_id, resolve_cli_path,
    resolve_repo_path, root_cause_id, run_manifest_invariant_fingerprint,
    severity_rank, strict_json_equal,
)

REQUIRED_INPUT_FIELDS = {
    "file", "line", "rule_id", "category", "severity",
    "title", "evidence", "why", "repro", "suggestion",
}

# 可选、若存在则原样透传到 finding 记录
PASSTHROUGH_OPTIONAL = (
    "dataflow_path", "origin_trace", "engine", "native_rule_id",
    "review_reason", "missing_evidence", "confidence",
    "root_cause", "source_candidate_ids", "provenance", "related_locations",
)

# 取证闸（C）：以下「条件触发型」类别的缺陷只有在关键值（Context/输入/调用线程）
# 回溯到终端源头后才成立。verifier 须用 nav_tools `trace-origin` 取证并把源头链写入
# `dataflow_path`（或显式 `origin_trace`）。缺失源头链的此类 finding 视为**取证未完成**，
# 转入 needs-review——防止「仅凭 sink 模式」的未取证结论混入正式报告。
ORIGIN_REQUIRED_PREFIXES = (
    "stability/static-context-leak",
    "perf/main-thread",
    "performance/thread-starvation",
    "performance/main-thread",
    "security/exported",
    "security/ipc-caller-unverified",
    "security/webview",
    "security/deeplink",
)
ORIGIN_REQUIRED_SUBSTRINGS = ("-data-flow", "unvalidated-input", "越权")
EXPECTED_TOOL_ENGINES = {"semgrep", "detekt", "pmd", "lint"}
ENGINE_STATUSES = {"complete", "partial", "failed", "skipped", "not_applicable"}


def _needs_origin(category: str) -> bool:
    c = category or ""
    if any(c.startswith(p) for p in ORIGIN_REQUIRED_PREFIXES):
        return True
    return any(s in c for s in ORIGIN_REQUIRED_SUBSTRINGS)


def _has_origin(cand: dict) -> bool:
    return bool(cand.get("dataflow_path")) or bool(cand.get("origin_trace"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--findings", default=".scan/findings.json")
    ap.add_argument("--needs-review", default=".scan/needs-review.json")
    ap.add_argument(
        "--verified-glob", default="",
        help="从匹配的 verifier JSON 对象聚合输入；设置后 stdin 必须为空",
    )
    ap.add_argument(
        "--verify-coverage", default=".scan/tmp/verify_coverage.json",
        help="verified-glob 模式下用于断言所有 verifier 批次均返回的覆盖率清单",
    )
    ap.add_argument("--engine-results", default=".scan/tmp/engine-results.json")
    ap.add_argument(
        "--hunt-coverage-result",
        default=".scan/tmp/hunt_perspective_coverage.json",
    )
    ap.add_argument(
        "--gap-audit-coverage",
        default=".scan/tmp/gap_audit_coverage.json",
    )
    ap.add_argument(
        "--receipt", default=None,
        help="成功合并回执；render_report 用它阻止缺失 verifier 的假完成报告",
    )
    ap.add_argument("--run-manifest", default=".scan/tmp/run_manifest.json")
    # --commit 仅为兼容旧调用而保留，已忽略（无 ledger 后报告不含 commit/时间）
    ap.add_argument("--commit", default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()
    findings_path = _repo_path(repo, args.findings)
    needs_review_path = _repo_path(repo, args.needs_review)
    receipt_path = (
        _repo_path(repo, args.receipt)
        if args.receipt else findings_path.parent / "tmp/merge_receipt.json"
    )
    verify_coverage_path = _repo_path(repo, args.verify_coverage)
    engine_results_path = _repo_path(repo, args.engine_results)
    hunt_coverage_path = _repo_path(repo, args.hunt_coverage_result)
    gap_audit_coverage_path = _repo_path(repo, args.gap_audit_coverage)
    run_manifest_path = _repo_path(repo, args.run_manifest)
    if receipt_path.exists():
        receipt_path.unlink()
    if args.verified_glob:
        # A failed re-merge must not leave prior-run final JSON looking current.
        for stale_output in (findings_path, needs_review_path):
            if stale_output.is_file():
                stale_output.unlink()

    raw = sys.stdin.read().strip()
    try:
        if args.verified_glob:
            if raw:
                print("--verified-glob 与 stdin 输入不能同时使用", file=sys.stderr)
                return 2
            payload = _load_verified_glob(
                args.verified_glob, verify_coverage_path, repo,
            )
        else:
            payload = json.loads(raw) if raw else {"confirmed": [], "needs_review": []}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"无法读取 verifier 输出: {exc}", file=sys.stderr)
        return 2
    if isinstance(payload, list):
        confirmed_candidates = payload
        review_candidates: list[dict] = []
    elif isinstance(payload, dict):
        confirmed_candidates = payload.get("confirmed", [])
        review_candidates = payload.get("needs_review", [])
    else:
        print("stdin 必须是 JSON 对象或兼容的 JSON 数组", file=sys.stderr)
        return 2
    if not isinstance(confirmed_candidates, list) or not isinstance(review_candidates, list):
        print("confirmed / needs_review 必须是 JSON 数组", file=sys.stderr)
        return 2

    records: dict[str, dict] = {}
    review_records: dict[str, dict] = {}
    duplicates = 0
    semantic_duplicates = 0
    exact_duplicates = 0
    confirmed_review_conflicts = 0
    without_root_cause = 0
    moved_no_origin = 0

    for cand in confirmed_candidates:
        if not isinstance(cand, dict):
            print(f"finding 必须是对象: {cand}", file=sys.stderr)
            return 2
        missing = REQUIRED_INPUT_FIELDS - cand.keys()
        if missing:
            print(f"候选缺失字段 {missing}: {cand}", file=sys.stderr)
            return 2

        # 取证闸（C）：证据不足不是「无问题」。保留到人工/后续复核队列。
        if _needs_origin(cand.get("category", "")) and not _has_origin(cand):
            moved = dict(cand)
            moved["review_reason"] = "条件触发型问题尚缺可信 source→sink/origin 调用链"
            moved["missing_evidence"] = ["dataflow_path 或 origin_trace"]
            _, semantic, duplicate = _put_review(review_records, moved)
            if not semantic:
                without_root_cause += 1
            if duplicate:
                duplicates += 1
                semantic_duplicates += int(semantic)
                exact_duplicates += int(not semantic)
            moved_no_origin += 1
            continue

        key, fid, semantic = _identity(cand)
        if not semantic:
            without_root_cause += 1
        if key in records:
            duplicates += 1
            semantic_duplicates += int(semantic)
            exact_duplicates += int(not semantic)
            records[key] = _merge_records(records[key], _confirmed_record(cand, fid, semantic))
            continue

        records[key] = _confirmed_record(cand, fid, semantic)

    for cand in review_candidates:
        if not isinstance(cand, dict):
            print(f"needs_review finding 必须是对象: {cand}", file=sys.stderr)
            return 2
        missing = {"file", "line", "rule_id", "category", "severity", "title", "evidence"} - cand.keys()
        if missing:
            print(f"needs_review 候选缺失字段 {missing}: {cand}", file=sys.stderr)
            return 2
        if not cand.get("review_reason"):
            cand = {**cand, "review_reason": "verifier 未能获得足够证据做出可靠结论"}
        _, semantic, duplicate = _put_review(review_records, cand)
        if not semantic:
            without_root_cause += 1
        if duplicate:
            duplicates += 1
            semantic_duplicates += int(semantic)
            exact_duplicates += int(not semantic)

    # 多个 verifier 对同一根因给出不同置信结论时，证据完整的 confirmed 胜出，
    # 避免同一 finding 同时出现在正式报告和待复核报告中。
    for key in records:
        if key in review_records:
            confirmed_review_conflicts += 1
            review_records.pop(key, None)

    findings_list = list(records.values())
    needs_review_list = list(review_records.values())

    out = {
        "findings_total": len(findings_list),
        "needs_review_total": len(needs_review_list),
        "findings_duplicate": duplicates,
        "semantic_duplicates_merged": semantic_duplicates,
        "exact_duplicates_merged": exact_duplicates,
        "confirmed_review_conflicts_resolved": confirmed_review_conflicts,
        "records_without_root_cause": without_root_cause,
        "moved_to_review_no_origin": moved_no_origin,
    }
    run_manifest: dict = {}
    if run_manifest_path.is_file():
        try:
            loaded = json.loads(run_manifest_path.read_text(encoding="utf-8"))
            run_manifest = loaded if isinstance(loaded, dict) else {}
        except (OSError, json.JSONDecodeError):
            pass
    verified_files = _verified_paths(args.verified_glob, repo) if args.verified_glob else []
    artifact_paths: list[Path] = []
    missing_inputs: list[str] = []
    if args.verified_glob:
        if (
            type(run_manifest.get("schema_version")) is not int
            or run_manifest.get("schema_version") != 1
            or run_manifest.get("source_only") is not True
            or not isinstance(run_manifest.get("run_id"), str)
            or not run_manifest.get("run_id")
            or type(run_manifest.get("config_trusted")) is not bool
        ):
            missing_inputs.append("run_manifest missing source-only run identity")
        current_fingerprint = current_skill_fingerprint()
        if run_manifest.get("skill_fingerprint") != current_fingerprint:
            missing_inputs.append("scan-android skill/rules changed after scope preparation")
        verify_inputs = _verify_input_paths(repo, verify_coverage_path)
        project_path = repo / ".scan/tmp/project.json"
        scope_path = repo / ".scan/tmp/scope.txt"
        hunt_scope_path = repo / ".scan/tmp/hunt_scope.txt"
        context_scope_path = repo / ".scan/tmp/context_scope.txt"
        scope_meta_path = repo / ".scan/tmp/scope_meta.json"
        required_paths = [
            engine_results_path, verify_coverage_path,
            project_path, scope_path, hunt_scope_path, context_scope_path, scope_meta_path,
            *verify_inputs, *verified_files,
        ]
        try:
            project = json.loads(project_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            project = {}
        effective_config = project.get("config", {}) if isinstance(project, dict) else {}
        if not isinstance(effective_config, dict):
            effective_config = {}
            missing_inputs.append("project.config missing or invalid")
        config_digest = hashlib.sha256(
            json.dumps(effective_config, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        if run_manifest.get("config_fingerprint") != config_digest:
            missing_inputs.append("project config no longer matches run_manifest fingerprint")
        expected_hunt_policy = effective_hunt_policy(effective_config)
        if run_manifest.get("effective_hunt_policy") != expected_hunt_policy:
            missing_inputs.append("effective Hunter policy changed or missing after scope preparation")
        project_excluded = effective_excluded_engines(effective_config)
        if run_manifest.get("effective_excluded_engines", []) != project_excluded:
            missing_inputs.append("effective excluded engines changed after scope preparation")
        try:
            engine_results = json.loads(engine_results_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            engine_results = {}
        if isinstance(engine_results, dict):
            if engine_results.get("config_fingerprint") != run_manifest.get("config_fingerprint"):
                missing_inputs.append("engine run config does not match scope run")
            if engine_results.get("config_trusted") is not run_manifest.get("config_trusted"):
                missing_inputs.append("engine run config trust does not match scope run")
            if engine_results.get("effective_excluded_engines") != project_excluded:
                missing_inputs.append("engine run exclusions do not match scope run")
            missing_inputs.extend(_engine_integrity_problems(engine_results))
        scope_snapshot = (
            engine_results.get("scope_snapshot", [])
            if isinstance(engine_results, dict) else []
        )
        if not isinstance(engine_results, dict) or "scope_snapshot" not in engine_results:
            missing_inputs.append("engine-results.scope_snapshot missing")
        if not isinstance(engine_results, dict) or type(
            engine_results.get("scope_changed_during_scan")
        ) is not bool:
            missing_inputs.append("engine-results.scope_changed_during_scan missing or invalid")
        if not isinstance(scope_snapshot, list):
            missing_inputs.append("engine-results.scope_snapshot must be an array")
            scope_snapshot = []
        for index, receipt in enumerate(scope_snapshot):
            if not isinstance(receipt, dict):
                missing_inputs.append(f"engine-results.scope_snapshot[{index}] invalid")
                continue
            try:
                normalized = _validated_repo_file(
                    repo, receipt.get("file"), f"engine-results.scope_snapshot[{index}].file",
                )
                source_path = repo / normalized
                digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
            except (OSError, ValueError) as exc:
                missing_inputs.append(str(exc))
                continue
            if receipt.get("sha256") != digest:
                missing_inputs.append(f"engine scope source changed: {normalized}")
            required_paths.append(source_path)
        if isinstance(engine_results, dict) and engine_results.get("scope_changed_during_scan") is True:
            missing_inputs.append("engine scope changed during scan")
        if _ai_hunt_required(repo, run_manifest):
            tmp_dir = repo / ".scan/tmp"
            hunt_input_coverage = tmp_dir / "hunt_coverage.json"
            gap_plan = tmp_dir / "gap_audit_plan.json"
            required_paths.extend([
                hunt_input_coverage, hunt_coverage_path,
                tmp_dir / "relation_graph.json", gap_plan,
                gap_audit_coverage_path,
            ])

            artifact_groups = {
                ".scan/tmp/hunt_batch_*.json": sorted(tmp_dir.glob("hunt_batch_*.json")),
                ".scan/tmp/repo_map_*.md": sorted(tmp_dir.glob("repo_map_*.md")),
                ".scan/tmp/repo_map_*.meta.json": sorted(tmp_dir.glob("repo_map_*.meta.json")),
                ".scan/tmp/hunt_result_*.json": sorted(tmp_dir.glob("hunt_result_*.json")),
                ".scan/tmp/gap_audit_batch_*.json": sorted(tmp_dir.glob("gap_audit_batch_*.json")),
                ".scan/tmp/gap_prior_*.json": sorted(tmp_dir.glob("gap_prior_*.json")),
                ".scan/tmp/hunt_gap_result_*.json": sorted(tmp_dir.glob("hunt_gap_result_*.json")),
            }
            for label, paths in artifact_groups.items():
                if paths:
                    required_paths.extend(paths)
                else:
                    missing_inputs.append(label)

            try:
                input_coverage = json.loads(hunt_input_coverage.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                input_coverage = {}
            if (
                not isinstance(input_coverage, dict)
                or type(input_coverage.get("schema_version")) is not int
                or input_coverage.get("schema_version") != 3
                or input_coverage.get("coverage_ok") is not True
            ):
                missing_inputs.append("hunt_coverage.coverage_ok != true")
            elif (
                input_coverage.get("batch_size") != expected_hunt_policy["batch_size"]
                or input_coverage.get("token_budget") != expected_hunt_policy["token_budget"]
            ):
                missing_inputs.append("Hunter batch policy does not match run_manifest")
            else:
                for field, expected_path in (
                    ("scope_receipt", hunt_scope_path),
                    ("context_scope_receipt", context_scope_path),
                ):
                    receipt = input_coverage.get(field)
                    try:
                        bound_scope_path = resolve_repo_path(
                            repo,
                            receipt.get("file", "") if isinstance(receipt, dict) else "",
                            label=f"hunt_coverage.{field}.file",
                        )
                    except ValueError as exc:
                        missing_inputs.append(str(exc))
                        continue
                    if bound_scope_path != expected_path.resolve():
                        missing_inputs.append(f"hunt_coverage.{field} does not bind current scope")

            try:
                hunter_coverage = json.loads(hunt_coverage_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                hunter_coverage = {}
            if not isinstance(hunter_coverage, dict) or hunter_coverage.get("ok") is not True:
                missing_inputs.append("hunt_perspective_coverage.ok != true")
            else:
                min_samples = hunter_coverage.get("min_samples")
                if type(min_samples) is not int or min_samples < 1:
                    missing_inputs.append("hunt_perspective_coverage.min_samples missing or invalid")
                elif min_samples != expected_hunt_policy["samples"]:
                    missing_inputs.append("Hunter sample count does not match run_manifest")
                else:
                    live_hunter = check_hunt_coverage(
                        tmp_dir, hunt_input_coverage, min_samples, repo_root=repo,
                    )
                    if live_hunter.get("ok") is not True:
                        missing_inputs.append("live Hunter coverage revalidation failed")
                    elif not strict_json_equal(live_hunter, hunter_coverage):
                        missing_inputs.append("Hunter coverage receipt does not match live artifacts")

            try:
                gap_coverage = json.loads(gap_audit_coverage_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                gap_coverage = {}
            if not isinstance(gap_coverage, dict) or gap_coverage.get("ok") is not True:
                missing_inputs.append("gap_audit_coverage.ok != true")
            else:
                live_gap = check_gap_audit_coverage(
                    repo, tmp_dir, gap_plan, write_output=False,
                )
                if live_gap.get("ok") is not True:
                    missing_inputs.append("live gap-audit coverage revalidation failed")
                elif not strict_json_equal(live_gap, gap_coverage):
                    missing_inputs.append("gap-audit coverage receipt does not match live artifacts")

            # Bind the live production files reviewed by both AI passes.  If a
            # source changes after coverage checks, report rendering will
            # invalidate this receipt instead of presenting stale conclusions.
            if isinstance(input_coverage, dict):
                for detail in input_coverage.get("batches_detail", []):
                    if not isinstance(detail, dict):
                        continue
                    for rel in detail.get("files", []):
                        try:
                            normalized = _validated_repo_file(
                                repo, rel, "hunt_coverage.batches_detail.files",
                            )
                        except ValueError as exc:
                            missing_inputs.append(str(exc))
                            continue
                        required_paths.append(repo / normalized)
        missing_inputs.extend(
            _display_path(repo, path) for path in required_paths if not path.is_file()
        )
        artifact_paths = [*required_paths, *artifact_paths]
    artifact_paths = list(dict.fromkeys(path.resolve() for path in artifact_paths if path.is_file()))
    receipt_ok = not missing_inputs
    if receipt_ok:
        atomic_write_json(findings_path, {"schema_version": 4, "findings": findings_list})
        atomic_write_json(
            needs_review_path,
            {"schema_version": 2, "needs_review": needs_review_list},
        )
        artifact_paths.extend((findings_path.resolve(), needs_review_path.resolve()))
    atomic_write_json(receipt_path, {
        "ok": receipt_ok,
        "reason": "" if receipt_ok else "missing pipeline inputs: " + ", ".join(missing_inputs),
        "run_id": run_manifest.get("run_id", "unknown"),
        "skill_fingerprint": run_manifest.get("skill_fingerprint", ""),
        "run_manifest_invariants_sha256": run_manifest_invariant_fingerprint(run_manifest),
        "verified_glob": args.verified_glob or None,
        "verify_coverage": args.verify_coverage if args.verified_glob else None,
        "artifacts_sha256": [_artifact_digest(repo, path) for path in artifact_paths],
        "results": {"confirmed": len(findings_list), "needs_review": len(needs_review_list)},
        "stats": out,
    })
    if not receipt_ok:
        print("合并完整性回执失败: " + ", ".join(missing_inputs), file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False))
    return 0


def _repo_path(repo: Path, raw: str | Path) -> Path:
    return resolve_cli_path(repo, raw, label="pipeline path")


def _verified_paths(pattern: str, repo: Path) -> list[Path]:
    return expand_cli_glob(repo, pattern, label="verified output glob")


def _artifact_digest(repo: Path, path: Path) -> dict:
    resolved = path.resolve()
    return {
        "path": _display_path(repo, resolved),
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
    }


def _display_path(repo: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo).as_posix()
    except ValueError:
        return str(path.resolve())


def _validated_repo_file(repo: Path, value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or Path(value).is_absolute():
        raise ValueError(f"{label} 必须是仓库相对文件路径")
    resolved = (repo / value).resolve()
    try:
        rel = resolved.relative_to(repo.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"{label} 越出仓库: {value}") from exc
    if not resolved.is_file():
        raise ValueError(f"{label} 文件不存在: {rel}")
    return rel


def _validate_verified_locations(repo: Path, record: dict, source: Path) -> None:
    """Reject model-created paths before they are persisted or exposed as links."""
    record["file"] = _validated_repo_file(repo, record.get("file"), f"{source}: file")
    root = record.get("root_cause")
    if isinstance(root, dict) and "primary_file" in root:
        root["primary_file"] = _validated_repo_file(
            repo, root["primary_file"], f"{source}: root_cause.primary_file",
        )
    for field in ("dataflow_path", "origin_trace", "related_locations"):
        locations = record.get(field)
        if locations is None:
            continue
        if not isinstance(locations, list):
            raise ValueError(f"{source}: {field} 必须是数组")
        for index, location in enumerate(locations):
            if not isinstance(location, dict):
                raise ValueError(f"{source}: {field}[{index}] 必须是对象")
            if "file" in location:
                location["file"] = _validated_repo_file(
                    repo, location["file"], f"{source}: {field}[{index}].file",
                )


def _verify_input_paths(repo: Path, coverage_path: Path) -> list[Path]:
    try:
        coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    batch_files = coverage.get("batch_files", []) if isinstance(coverage, dict) else []
    if not isinstance(batch_files, list):
        return []
    return [
        _repo_path(repo, raw).resolve()
        for raw in batch_files if isinstance(raw, str)
    ]


def _ai_hunt_required(repo: Path, run_manifest: dict | None = None) -> bool:
    # Use the scanner-generated invocation manifest rather than re-reading raw
    # target configuration at the decision point.
    manifest = run_manifest if isinstance(run_manifest, dict) else {}
    excluded = manifest.get("effective_excluded_engines", [])
    if isinstance(excluded, list) and "ai" in excluded:
        return False
    hunt_scope = repo / ".scan/tmp/hunt_scope.txt"
    try:
        return bool(hunt_scope.read_text(encoding="utf-8").strip())
    except OSError:
        return False


def _engine_integrity_problems(engine_results: dict) -> list[str]:
    stats = engine_results.get("engine_stats")
    if not isinstance(stats, list) or not all(isinstance(item, dict) for item in stats):
        return ["engine-results.engine_stats missing or invalid"]
    names = [item.get("engine") for item in stats]
    if any(not isinstance(name, str) or not name for name in names):
        return ["engine-results contains an invalid engine name"]
    problems: list[str] = []
    if len(names) != len(set(names)):
        problems.append("engine-results contains duplicate engine stats")
    missing = EXPECTED_TOOL_ENGINES - set(names)
    if missing:
        problems.append("engine-results omitted engines: " + ", ".join(sorted(missing)))
    unexpected = set(names) - EXPECTED_TOOL_ENGINES - {"scope_integrity"}
    if unexpected:
        problems.append("engine-results contains unknown engines: " + ", ".join(sorted(unexpected)))
    statuses = [item.get("status") for item in stats]
    if any(status not in ENGINE_STATUSES for status in statuses):
        problems.append("engine-results contains invalid engine status")
        return problems
    expected_status = (
        "incomplete" if set(statuses) & {"partial", "failed"}
        else "complete_with_skips" if "skipped" in statuses
        else "complete"
    )
    if engine_results.get("status") != expected_status:
        problems.append("engine-results overall status does not match per-engine stats")
    if engine_results.get("scan_complete") is not (expected_status == "complete"):
        problems.append("engine-results.scan_complete does not match per-engine stats")

    incomplete_names = sorted(
        str(item["engine"])
        for item in stats if item.get("status") in {"partial", "failed"}
    )
    skipped_stats = [item for item in stats if item.get("status") == "skipped"]
    expected_gaps = [
        {"engine": item["engine"], "reason": item.get("reason", "skipped")}
        for item in skipped_stats
    ]
    expected_used = [
        str(item["engine"])
        for item in stats
        if item.get("engine") in EXPECTED_TOOL_ENGINES
        and item.get("status") in {"complete", "partial"}
    ]
    if engine_results.get("configured_complete") is not (not incomplete_names):
        problems.append("engine-results.configured_complete does not match per-engine stats")
    if engine_results.get("coverage_complete") is not (
        not incomplete_names and not skipped_stats
    ):
        problems.append("engine-results.coverage_complete does not match per-engine stats")
    if engine_results.get("incomplete_engines") != incomplete_names:
        problems.append("engine-results.incomplete_engines does not match per-engine stats")
    if engine_results.get("coverage_gaps") != expected_gaps:
        problems.append("engine-results.coverage_gaps does not match skipped engines")
    if engine_results.get("engines_used") != expected_used:
        problems.append("engine-results.engines_used does not match per-engine stats")
    return problems


def _confirmed_record(cand: dict, fid: str, semantic: bool) -> dict:
    record = {
        "id": fid,
        "file": cand["file"],
        "line": int(cand["line"]),
        "end_line": int(cand.get("end_line", cand["line"])),
        "rule_id": cand["rule_id"],
        "category": cand["category"],
        "severity": cand["severity"],
        "title": cand["title"],
        "evidence": cand["evidence"],
        "why": cand["why"],
        "repro": cand["repro"],
        "suggestion": cand["suggestion"],
        "status": "open",
        "dedup_scope": "root_cause" if semantic else "exact_location",
    }
    for optional_key in PASSTHROUGH_OPTIONAL:
        if cand.get(optional_key):
            record[optional_key] = cand[optional_key]
    return record


def _put_review(records: dict[str, dict], cand: dict) -> tuple[str, bool, bool]:
    key, fid, semantic = _identity(cand)
    record = {
        "id": fid,
        "file": cand["file"],
        "line": int(cand["line"]),
        "end_line": int(cand.get("end_line", cand["line"])),
        "rule_id": cand["rule_id"],
        "category": cand["category"],
        "severity": cand["severity"],
        "title": cand["title"],
        "evidence": cand["evidence"],
        "why": cand.get("why", ""),
        "repro": cand.get("repro", ""),
        "suggestion": cand.get("suggestion", ""),
        "status": "needs_review",
        "review_reason": cand.get("review_reason", "证据不足"),
        "dedup_scope": "root_cause" if semantic else "exact_location",
    }
    for optional_key in PASSTHROUGH_OPTIONAL:
        if cand.get(optional_key):
            record[optional_key] = cand[optional_key]
    duplicate = key in records
    records[key] = _merge_records(records[key], record) if duplicate else record
    return key, semantic, duplicate


def _richer(left: dict, right: dict) -> dict:
    """Keep the duplicate carrying more concrete evidence and trace material."""
    def score(item: dict) -> int:
        return sum(len(str(item.get(k, ""))) for k in (
            "evidence", "why", "repro", "suggestion", "dataflow_path", "origin_trace",
        ))
    return right if score(right) > score(left) else left


def _identity(cand: dict) -> tuple[str, str, bool]:
    root = cand.get("root_cause")
    if isinstance(root, dict):
        primary_file = root.get("primary_file")
        symbol = root.get("symbol")
        failure_mode = root.get("failure_mode")
        if all(isinstance(x, str) and x.strip() for x in (primary_file, symbol, failure_mode)):
            rid = root_cause_id(primary_file, symbol, failure_mode)
            return f"root:{rid}", rid, True
    fid = finding_id(cand["file"], int(cand["line"]), cand["category"], cand["rule_id"])
    return f"exact:{fid}", fid, False


def _merge_records(left: dict, right: dict) -> dict:
    """Merge one remediation root while retaining every manifestation and source."""
    richer = dict(_richer(left, right))
    if severity_rank(left.get("severity", "info")) < severity_rank(right.get("severity", "info")):
        richer["severity"] = left.get("severity", "info")
    else:
        richer["severity"] = right.get("severity", "info")

    locations: list[dict] = []
    for item in (left, right):
        locations.append({
            "file": item.get("file", ""),
            "line": int(item.get("line", 0)),
            "end_line": int(item.get("end_line", item.get("line", 0))),
            "rule_id": item.get("rule_id", ""),
            "category": item.get("category", ""),
            "title": item.get("title", ""),
        })
        if isinstance(item.get("related_locations"), list):
            locations.extend(x for x in item["related_locations"] if isinstance(x, dict))
    richer["related_locations"] = _dedup_dicts(locations, ("file", "line", "rule_id", "category"))

    source_ids: list[str] = []
    for item in (left, right):
        if isinstance(item.get("source_candidate_ids"), list):
            source_ids.extend(str(x) for x in item["source_candidate_ids"] if str(x))
        if item.get("candidate_id"):
            source_ids.append(str(item["candidate_id"]))
    if source_ids:
        richer["source_candidate_ids"] = list(dict.fromkeys(source_ids))

    provenance: list[dict] = []
    for item in (left, right):
        if isinstance(item.get("provenance"), list):
            provenance.extend(x for x in item["provenance"] if isinstance(x, dict))
    if provenance:
        richer["provenance"] = _dedup_dicts(provenance)
    richer["merged_manifestations"] = len(richer["related_locations"])
    return richer


def _dedup_dicts(items: list[dict], fields: tuple[str, ...] | None = None) -> list[dict]:
    seen: set[tuple | str] = set()
    result: list[dict] = []
    for item in items:
        key: tuple | str
        if fields:
            key = tuple(item.get(field) for field in fields)
        else:
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _load_verified_glob(pattern: str, coverage_path: Path, repo: Path) -> dict:
    files = _verified_paths(pattern, repo)
    if not files:
        raise ValueError(f"没有 verifier 输出匹配: {pattern}")
    coverage_file = coverage_path
    if not coverage_file.is_file():
        raise ValueError(f"verifier 覆盖率清单不存在: {coverage_file}")
    coverage = json.loads(coverage_file.read_text(encoding="utf-8"))
    if (
        not isinstance(coverage, dict)
        or type(coverage.get("schema_version")) is not int
        or coverage.get("schema_version") != 2
        or coverage.get("coverage_ok") is not True
    ):
        raise ValueError(f"verifier 覆盖率清单无效或 coverage_ok=false: {coverage_file}")
    batch_files = coverage.get("batch_files")
    if not isinstance(batch_files, list) or not all(isinstance(x, str) for x in batch_files):
        raise ValueError(f"verifier 覆盖率清单缺少合法 batch_files: {coverage_file}")
    if (
        type(coverage.get("candidates_input")) is not int
        or type(coverage.get("candidates_batched")) is not int
        or type(coverage.get("batches")) is not int
        or coverage["candidates_input"] != coverage["candidates_batched"]
        or coverage.get("batches") != len(batch_files)
    ):
        raise ValueError(f"verifier 覆盖率计数不守恒: {coverage_file}")
    _validate_verify_coverage_artifacts(coverage, repo, coverage_file)
    expected = {
        _repo_path(repo, raw).resolve().with_name(
            Path(raw).name.replace("verify_batch_", "verified_batch_", 1)
        )
        for raw in batch_files
    }
    actual = {path.resolve() for path in files}
    missing = sorted(str(p) for p in expected - actual)
    extra = sorted(str(p) for p in actual - expected)
    if missing or extra:
        raise ValueError(
            f"verifier 批次不完整：missing={missing or []}, extra={extra or []}"
        )
    confirmed: list[dict] = []
    needs_review: list[dict] = []
    for path in files:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            raise ValueError(f"verifier 输出必须是对象: {path}")
        if not isinstance(obj.get("confirmed", []), list) or not isinstance(obj.get("needs_review", []), list):
            raise ValueError(f"verifier 输出数组字段无效: {path}")
        name = path.name
        try:
            batch_index = int(name.removeprefix("verified_batch_").removesuffix(".json"))
        except ValueError as exc:
            raise ValueError(f"verifier 输出文件名无法解析批次编号: {path}") from exc
        input_path = path.with_name(f"verify_batch_{batch_index}.json")
        input_obj = json.loads(input_path.read_text(encoding="utf-8"))
        if not isinstance(input_obj, list):
            raise ValueError(f"verifier 输入批次必须是数组: {input_path}")
        _validate_adjudication(obj, path, batch_index, input_obj)
        for record in obj.get("confirmed", []) + obj.get("needs_review", []):
            if not isinstance(record, dict):
                raise ValueError(f"verifier finding 必须是对象: {path}")
            _validate_verified_locations(repo, record, path)
        confirmed.extend(obj.get("confirmed", []))
        needs_review.extend(obj.get("needs_review", []))
    return {"confirmed": confirmed, "needs_review": needs_review}


def _validate_adjudication(
    obj: dict, path: Path, batch_index: int, input_items: int | list[dict],
) -> None:
    input_count = input_items if isinstance(input_items, int) else len(input_items)
    fields = (
        "batch", "candidates_input", "candidates_adjudicated",
        "false_positive_count", "duplicates_merged_count",
    )
    if any(type(obj.get(field)) is not int for field in fields):
        raise ValueError(f"verifier 完整性回执缺失或类型错误: {path}")
    if obj["batch"] != batch_index:
        raise ValueError(f"verifier batch 字段与文件名不一致: {path}")
    if obj["candidates_input"] != input_count or obj["candidates_adjudicated"] != input_count:
        raise ValueError(
            f"verifier 未完整处理输入: {path} input={input_count}, "
            f"reported={obj['candidates_input']}/{obj['candidates_adjudicated']}"
        )
    false_count = obj["false_positive_count"]
    duplicate_count = obj["duplicates_merged_count"]
    if false_count < 0 or duplicate_count < 0:
        raise ValueError(f"verifier 完整性计数不能为负数: {path}")
    accounted = (
        len(obj.get("confirmed", [])) + len(obj.get("needs_review", []))
        + false_count + duplicate_count
    )
    if accounted != input_count:
        raise ValueError(
            f"verifier 判定计数不守恒: {path} accounted={accounted}, input={input_count}"
        )
    if isinstance(input_items, list):
        input_by_id = {
            str(item.get("candidate_id")): item for item in input_items
            if isinstance(item, dict) and item.get("candidate_id")
        }
        input_ids = set(input_by_id)
        if len(input_ids) != input_count:
            raise ValueError(f"verifier 输入 candidate_id 缺失或重复: {path}")
        false_ids = obj.get("false_positive_ids")
        if (
            not isinstance(false_ids, list)
            or not all(isinstance(value, str) and value for value in false_ids)
            or len(false_ids) != len(set(false_ids))
            or len(false_ids) != false_count
        ):
            raise ValueError(f"verifier false_positive_ids 与计数不一致: {path}")
        unknown_false = set(false_ids) - input_ids
        if unknown_false:
            raise ValueError(
                f"verifier false_positive_ids 含未知 ID: {path} ids={sorted(unknown_false)}"
            )
        emitted_ids: set[str] = set()
        for record in obj.get("confirmed", []) + obj.get("needs_review", []):
            root = record.get("root_cause") if isinstance(record, dict) else None
            if not isinstance(root, dict) or not all(
                isinstance(root.get(field), str) and root.get(field).strip()
                for field in ("primary_file", "symbol", "failure_mode")
            ):
                raise ValueError(f"verifier 输出缺少结构化 root_cause: {path}")
            source_ids = record.get("source_candidate_ids")
            provenance = record.get("provenance")
            if not isinstance(source_ids, list) or not source_ids or not all(isinstance(x, str) for x in source_ids):
                raise ValueError(f"verifier 输出缺少 source_candidate_ids: {path}")
            if len(source_ids) != len(set(source_ids)):
                raise ValueError(f"verifier finding 重复 source_candidate_ids: {path}")
            if not isinstance(provenance, list) or not provenance or not all(isinstance(x, dict) for x in provenance):
                raise ValueError(f"verifier 输出缺少 provenance: {path}")
            unknown = set(source_ids) - input_ids
            if unknown:
                raise ValueError(f"verifier 输出引用未知 candidate_id: {path} ids={sorted(unknown)}")
            repeated = emitted_ids & set(source_ids)
            if repeated:
                raise ValueError(f"同一 candidate_id 被输出到多个 finding: {path} ids={sorted(repeated)}")
            emitted_ids.update(source_ids)
            expected_provenance: list[dict] = []
            for source_id in source_ids:
                values = input_by_id[source_id].get("provenance", [])
                if isinstance(values, list):
                    expected_provenance.extend(
                        value for value in values if isinstance(value, dict)
                    )
            actual_provenance = {
                json.dumps(value, sort_keys=True, ensure_ascii=False) for value in provenance
            }
            expected_provenance_set = {
                json.dumps(value, sort_keys=True, ensure_ascii=False)
                for value in expected_provenance
            }
            if len(actual_provenance) != len(provenance) or actual_provenance != expected_provenance_set:
                raise ValueError(
                    f"verifier finding provenance 未按输入 ID 原样守恒: {path}"
                )
        output_records = len(obj.get("confirmed", [])) + len(obj.get("needs_review", []))
        expected_emitted = output_records + duplicate_count
        if len(emitted_ids) != expected_emitted:
            raise ValueError(
                f"verifier provenance 数量不守恒: {path} "
                f"emitted_ids={len(emitted_ids)}, expected={expected_emitted}"
            )
        if emitted_ids & set(false_ids):
            raise ValueError(f"candidate_id 同时被判为 finding 与 false positive: {path}")
        if emitted_ids | set(false_ids) != input_ids:
            missing_ids = sorted(input_ids - emitted_ids - set(false_ids))
            raise ValueError(
                f"verifier 未逐 ID 完整处理输入: {path} missing={missing_ids}"
            )


def _validate_verify_coverage_artifacts(coverage: dict, repo: Path, source: Path) -> None:
    """Bind verifier batches to the exact candidate inputs used to build them."""
    inputs = coverage.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise ValueError(f"verifier 覆盖率缺候选输入回执: {source}")
    candidate_total = 0
    for index, receipt in enumerate(inputs):
        if not isinstance(receipt, dict):
            raise ValueError(f"verifier 输入回执无效: {source} inputs[{index}]")
        try:
            path = resolve_repo_path(
                repo,
                receipt.get("file", ""),
                label=f"verify coverage inputs[{index}].file",
            )
            raw = path.read_bytes()
        except (OSError, ValueError) as exc:
            raise ValueError(str(exc)) from exc
        if receipt.get("sha256") != hashlib.sha256(raw).hexdigest():
            raise ValueError(f"verifier 候选输入在分批后发生变化: {path}")
        count = receipt.get("candidates")
        if type(count) is not int or count < 0:
            raise ValueError(f"verifier 输入候选计数无效: {source} inputs[{index}]")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"verifier 候选输入 JSON 无效: {path}: {exc}") from exc
        if isinstance(payload, list):
            actual_count = len(payload)
        elif isinstance(payload, dict) and isinstance(payload.get("candidates"), list):
            actual_count = len(payload["candidates"])
        else:
            raise ValueError(f"verifier 候选输入缺 candidates 数组: {path}")
        if actual_count != count:
            raise ValueError(f"verifier 候选输入计数在分批后发生变化: {path}")
        candidate_total += count
    if candidate_total != coverage.get("candidates_input"):
        raise ValueError(f"verifier 输入回执候选总数不守恒: {source}")

    batch_files = coverage.get("batch_files", [])
    receipts = coverage.get("batch_receipts")
    if not isinstance(receipts, list) or len(receipts) != len(batch_files):
        raise ValueError(f"verifier 批次哈希回执缺失: {source}")
    expected_paths = {
        resolve_repo_path(repo, raw, label="verify coverage batch file")
        for raw in batch_files
    }
    seen_paths: set[Path] = set()
    batched_total = 0
    candidate_ids: set[str] = set()
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            raise ValueError(f"verifier 批次回执无效: {source} batch_receipts[{index}]")
        path = resolve_repo_path(
            repo,
            receipt.get("file", ""),
            label=f"verify coverage batch_receipts[{index}].file",
        )
        if path in seen_paths:
            raise ValueError(f"verifier 批次回执重复: {path}")
        seen_paths.add(path)
        try:
            raw = path.read_bytes()
            batch = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"verifier 批次不可读: {path}: {exc}") from exc
        if not isinstance(batch, list) or not all(isinstance(item, dict) for item in batch):
            raise ValueError(f"verifier 批次必须是对象数组: {path}")
        if receipt.get("sha256") != hashlib.sha256(raw).hexdigest():
            raise ValueError(f"verifier 批次在生成后发生变化: {path}")
        if type(receipt.get("candidates")) is not int or (
            receipt.get("candidates") != len(batch)
        ):
            raise ValueError(f"verifier 批次候选计数变化: {path}")
        batched_total += len(batch)
        for item in batch:
            candidate_id = item.get("candidate_id")
            if not isinstance(candidate_id, str) or not candidate_id or candidate_id in candidate_ids:
                raise ValueError(f"verifier 批次 candidate_id 缺失或重复: {path}")
            candidate_ids.add(candidate_id)
    if seen_paths != expected_paths:
        raise ValueError(f"verifier 批次回执与 batch_files 不一致: {source}")
    if batched_total != coverage.get("candidates_batched"):
        raise ValueError(f"verifier 批次回执总数不守恒: {source}")
    if type(coverage.get("candidate_ids_unique")) is not int or (
        coverage.get("candidate_ids_unique") != len(candidate_ids)
    ):
        raise ValueError(f"verifier candidate_ids_unique 回执不一致: {source}")


if __name__ == "__main__":
    sys.exit(main())
