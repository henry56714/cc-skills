#!/usr/bin/env python3
"""
check_hunt_coverage.py — AI 狩猎支线「文件证据 + 多视角覆盖」的事后断言。

`build_hunt_batches.py` 保证了【文件不漏分批】（确定性 + 覆盖率断言）；但「每批是否真的
把每个该过的狩猎视角都过了」是 hunter 子代理的编排约定，脚本管不到。本脚本把它也变成
【事后可机械核对】：

  - 期望（expected）：`hunt_coverage.json` 的 `batches_detail[*].expected_perspectives`
    —— 由 build_hunt_batches 据每批 tech_present 确定性算出（无 WebView 就不期望 webview 视角）。
  - 实际（covered）：每个 `hunt_result_*.json` 自带 `perspectives_covered` 与
    `case_ids_checked`、`files_reviewed`。后者记录每个实际读取文件的 sha256、行数和 Read 范围。

断言（任一不满足 → 退出码 1）：
  1. 每个独立样本都必须覆盖本批全部视角、case 和文件；不能靠多个不完整样本取并集；
  2. `files_reviewed` 必须与批次文件精确一致，sha256/line_count 与当前文件一致，
     ranges 合并后覆盖 1..line_count；
  3. 每批合法独立样本达到 --min-samples，且不接受重复 sample 或游离结果。

schema v2+ 不再维护与结果重复的 `hunt_attest_*.json`。当前 schema v3 还会绑定
scope/context 清单，并在检查时确定性重建批次与关系图；旧 schema v1 仅兼容原回执。

仅用 Python 标准库。读取仓库文件并只在 .scan/tmp 写 hunt_perspective_coverage.json。

退出码：0 = 文件证据与视角全部覆盖；1 = 文件/视角/采样/输入校验失败。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

from build_hunt_batches import build_batches
from lib_scan import resolve_cli_path, resolve_repo_path, strict_json_equal


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"__error__": str(e)}


def _snapshot(repo_root: Path, rel: str) -> tuple[str, int] | None:
    candidate = Path(rel)
    if candidate.is_absolute():
        return None
    try:
        path = (repo_root / candidate).resolve()
        path.relative_to(repo_root.resolve())
        data = path.read_bytes()
    except (OSError, ValueError):
        return None
    line_count = data.count(b"\n")
    if data and not data.endswith(b"\n"):
        line_count += 1
    return hashlib.sha256(data).hexdigest(), line_count


def _ranges_cover(ranges: object, line_count: int) -> bool:
    if not isinstance(ranges, list):
        return False
    if line_count == 0:
        return ranges == []
    normalized: list[tuple[int, int]] = []
    for item in ranges:
        if not isinstance(item, dict):
            return False
        start, end = item.get("start"), item.get("end")
        if (
            type(start) is not int or type(end) is not int
            or start < 1 or end < start or end > line_count
        ):
            return False
        normalized.append((start, end))
    cursor = 1
    for start, end in sorted(normalized):
        if start > cursor:
            return False
        cursor = max(cursor, end + 1)
    return cursor > line_count


def _validate_file_reads(
    reads: object, expected_files: set[str], repo_root: Path,
) -> list[str]:
    if not isinstance(reads, list):
        return ["缺 files_reviewed 数组"]
    problems: list[str] = []
    by_file: dict[str, dict] = {}
    for item in reads:
        if not isinstance(item, dict) or not isinstance(item.get("file"), str):
            problems.append("files_reviewed 含无效记录")
            continue
        rel = item["file"].replace("\\", "/")
        if rel in by_file:
            problems.append(f"重复文件回执: {rel}")
        by_file[rel] = item
    actual_files = set(by_file)
    if expected_files - actual_files:
        problems.append("漏读文件: " + ", ".join(sorted(expected_files - actual_files)))
    if actual_files - expected_files:
        problems.append("批外文件冒充覆盖: " + ", ".join(sorted(actual_files - expected_files)))
    for rel in sorted(expected_files & actual_files):
        current = _snapshot(repo_root, rel)
        item = by_file[rel]
        if current is None:
            problems.append(f"文件不可读或越界: {rel}")
            continue
        digest, line_count = current
        if item.get("sha256") != digest:
            problems.append(f"文件哈希不匹配: {rel}")
        if type(item.get("line_count")) is not int or item.get("line_count") != line_count:
            problems.append(f"文件行数不匹配: {rel}")
        if not _ranges_cover(item.get("ranges"), line_count):
            problems.append(f"读取范围未覆盖完整文件: {rel}")
    return problems


_CASE_STATUSES = {"no_signal", "mitigated", "candidate", "needs_context"}


_PLAN_COMPARE_FIELDS = (
    "schema_version", "total_input", "analyzed", "batched",
    "generated_excluded", "missing", "uncovered", "coverage_ok", "batches",
    "batch_size", "token_budget", "batching_strategy", "map_receipts_required",
    "relation_graph_stats", "tech_present", "marker_scan_truncated",
    "analysis_gaps", "batches_detail", "scope_receipt",
    "context_scope_receipt", "context_scope_path", "context_files",
)


def _receipted_input(
    cov: dict, field: str, repo_root: Path, *, optional: bool = False,
) -> tuple[Path | None, list[str]]:
    receipt = cov.get(field)
    if optional and receipt is None:
        return None, []
    if not isinstance(receipt, dict):
        return None, [f"{field} 缺失或不是对象"]
    raw_path = receipt.get("file")
    digest = receipt.get("sha256")
    if not isinstance(raw_path, str) or not raw_path or not isinstance(digest, str):
        return None, [f"{field} 缺合法 file/sha256"]
    try:
        path = resolve_repo_path(repo_root, raw_path, label=field)
        current = hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, ValueError) as exc:
        return None, [str(exc)]
    if current != digest:
        return path, [f"{field} 对应输入在分批后发生变化"]
    return path, []


def _validate_v3_plan(out_dir: Path, cov: dict, repo_root: Path) -> list[str]:
    """Rebuild the deterministic plan so a self-consistent subset cannot pass."""
    problems: list[str] = []
    if cov.get("schema_version") != 3:
        return ["当前完整性闸要求 hunt_coverage schema_version=3"]
    batch_size = cov.get("batch_size")
    token_budget = cov.get("token_budget")
    if type(batch_size) is not int or batch_size < 1:
        problems.append("hunt_coverage.batch_size 无效")
    if type(token_budget) is not int or token_budget < 1000:
        problems.append("hunt_coverage.token_budget 无效")
    scope_path, scope_problems = _receipted_input(cov, "scope_receipt", repo_root)
    context_path, context_problems = _receipted_input(
        cov, "context_scope_receipt", repo_root, optional=True,
    )
    problems.extend(scope_problems)
    problems.extend(context_problems)
    if problems or scope_path is None:
        return problems

    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=".hunt-plan-recheck-", dir=out_dir) as tmp:
            rebuilt_dir = Path(tmp)
            # An explicitly absent context receipt means the original build had
            # no context file. Pass a guaranteed-absent path to reproduce that.
            rebuilt_context = context_path or (rebuilt_dir / "absent-context-scope.txt")
            rebuilt = build_batches(
                repo_root, scope_path, rebuilt_dir, batch_size, token_budget,
                context_path=rebuilt_context,
            )
            for field in _PLAN_COMPARE_FIELDS:
                if not strict_json_equal(cov.get(field), rebuilt.get(field)):
                    problems.append(f"Hunter 计划字段与确定性重建不一致: {field}")

            expected_batch_paths = [
                (out_dir / f"hunt_batch_{index}.json").resolve()
                for index in range(int(rebuilt.get("batches", 0)))
            ]
            actual_batch_paths = {path.resolve() for path in out_dir.glob("hunt_batch_*.json")}
            if actual_batch_paths != set(expected_batch_paths):
                problems.append("hunt_batch 文件集合与确定性计划不一致")

            declared_batch_files = cov.get("batch_files")
            try:
                declared_paths = [
                    resolve_repo_path(repo_root, raw, label="hunt_coverage.batch_files")
                    for raw in declared_batch_files
                ] if isinstance(declared_batch_files, list) and all(
                    isinstance(raw, str) for raw in declared_batch_files
                ) else []
            except ValueError as exc:
                problems.append(str(exc))
                declared_paths = []
            if declared_paths != expected_batch_paths:
                problems.append("hunt_coverage.batch_files 与实际计划不一致")

            for index in range(int(rebuilt.get("batches", 0))):
                actual = _load_json(out_dir / f"hunt_batch_{index}.json")
                expected = _load_json(rebuilt_dir / f"hunt_batch_{index}.json")
                if not strict_json_equal(actual, expected):
                    problems.append(f"hunt_batch_{index}.json 与确定性重建不一致")

            try:
                graph_path = resolve_repo_path(
                    repo_root, cov.get("relation_graph_path", ""),
                    label="hunt_coverage.relation_graph_path",
                )
            except ValueError as exc:
                problems.append(str(exc))
                graph_path = out_dir / "__invalid_relation_graph__"
            if graph_path.resolve() != (out_dir / "relation_graph.json").resolve():
                problems.append("relation_graph_path 未指向当前 Hunter 输出目录")
            if not strict_json_equal(
                _load_json(graph_path), _load_json(rebuilt_dir / "relation_graph.json")
            ):
                problems.append("relation_graph.json 与当前源码的确定性重建不一致")
    except (OSError, ValueError, TypeError) as exc:
        problems.append(f"无法确定性重建 Hunter 计划: {exc}")
    return list(dict.fromkeys(problems))


def _validate_case_assessments(
    obj: dict,
    expected_cases: set[str],
    expected_files: set[str],
    repo_root: Path,
) -> list[str]:
    """Require a per-case judgment, not a copied checklist of ids."""
    if not expected_cases:
        return []
    assessments = obj.get("case_assessments")
    if not isinstance(assessments, list):
        return ["缺 case_assessments 数组（case_ids_checked 不能代替逐项判断）"]
    problems: list[str] = []
    by_id: dict[str, dict] = {}
    for assessment in assessments:
        if not isinstance(assessment, dict) or not isinstance(assessment.get("case_id"), str):
            problems.append("case_assessments 含无效记录")
            continue
        case_id = assessment["case_id"]
        if case_id in by_id:
            problems.append(f"重复 case 判断: {case_id}")
            continue
        by_id[case_id] = assessment

    missing = expected_cases - set(by_id)
    if missing:
        problems.append("漏 case 判断: " + ", ".join(sorted(missing)))
    extra = set(by_id) - expected_cases
    if extra:
        problems.append("计划外 case 判断: " + ", ".join(sorted(extra)))
    checked = obj.get("case_ids_checked")
    if not isinstance(checked, list) or not all(isinstance(x, str) for x in checked):
        problems.append("case_ids_checked 必须是字符串数组")
    elif set(checked) != set(by_id):
        problems.append("case_ids_checked 与 case_assessments 不一致")

    candidates = obj.get("candidates", [])
    candidate_rules = {
        item.get("rule_id") for item in candidates
        if isinstance(item, dict) and isinstance(item.get("rule_id"), str)
    }
    for case_id in sorted(expected_cases & set(by_id)):
        assessment = by_id[case_id]
        status = assessment.get("status")
        if status not in _CASE_STATUSES:
            problems.append(f"{case_id} status 无效")
            continue
        signals = assessment.get("signals_checked")
        if not isinstance(signals, list) or not signals or not all(
            isinstance(value, str) and value.strip() for value in signals
        ):
            problems.append(f"{case_id} 缺 signals_checked（至少写明实际检查的条件/不变量）")
        conclusion = assessment.get("conclusion")
        if not isinstance(conclusion, str) or len(conclusion.strip()) < 4:
            problems.append(f"{case_id} 缺有效 conclusion")
        evidence = assessment.get("evidence", [])
        if not isinstance(evidence, list):
            problems.append(f"{case_id} evidence 必须是数组")
            evidence = []
        if status in {"candidate", "mitigated"} and not evidence:
            problems.append(f"{case_id} 的 {status} 判断缺源码证据")
        for location in evidence:
            if not isinstance(location, dict):
                problems.append(f"{case_id} evidence 含无效记录")
                continue
            rel = location.get("file")
            line = location.get("line")
            if not isinstance(rel, str) or rel.replace("\\", "/") not in expected_files:
                problems.append(f"{case_id} evidence 指向批外或无效文件")
            if isinstance(line, bool) or not isinstance(line, int) or line < 1:
                problems.append(f"{case_id} evidence 缺有效行号")
            elif isinstance(rel, str) and rel.replace("\\", "/") in expected_files:
                snapshot = _snapshot(repo_root, rel.replace("\\", "/"))
                if snapshot is None or line > snapshot[1]:
                    problems.append(f"{case_id} evidence 行号超出文件范围")
        if status == "candidate" and case_id not in candidate_rules:
            problems.append(f"{case_id} 标为 candidate，但 candidates 中没有对应 rule_id")
        if status == "needs_context":
            problems.append(f"{case_id} 仍为 needs_context，不能宣称本样本完整")
    return problems


def _check_v2(
    out_dir: Path, cov: dict, min_samples: int, repo_root: Path,
) -> dict:
    upstream_gaps = cov.get("analysis_gaps", [])
    if cov.get("coverage_ok") is not True:
        return {
            "schema_version": cov.get("schema_version", 2),
            "ok": False,
            "error": "hunter 批次输入覆盖或分析完整性断言未通过",
            "analysis_gaps": upstream_gaps if isinstance(upstream_gaps, list) else [],
            "upstream_coverage_ok": cov.get("coverage_ok"),
        }
    if cov.get("map_receipts_required") is not True:
        return {
            "schema_version": cov.get("schema_version", 2),
            "ok": False,
                "error": "schema v2+ 必须启用 repo_map 导航回执，不能省略完整性闸",
        }
    expected_by_batch: dict[int, set[str]] = {}
    expected_cases_by_batch: dict[int, set[str]] = {}
    files_by_batch: dict[int, set[str]] = {}
    try:
        for detail in cov.get("batches_detail", []):
            if not isinstance(detail, dict):
                raise TypeError("batches_detail item must be an object")
            batch = int(detail["batch"])
            if batch in expected_by_batch:
                raise ValueError(f"duplicate batch {batch}")
            perspectives = detail.get("expected_perspectives", [])
            expected_cases = detail.get("expected_case_ids", [])
            files = detail.get("files", [])
            if (
                not isinstance(perspectives, list)
                or not all(isinstance(item, str) for item in perspectives)
                or not isinstance(files, list)
                or not all(isinstance(item, str) for item in files)
                or not isinstance(expected_cases, list)
                or not all(isinstance(item, str) for item in expected_cases)
            ):
                raise TypeError(f"batch {batch} perspectives/files/cases must be string arrays")
            expected_by_batch[batch] = set(perspectives)
            expected_cases_by_batch[batch] = set(expected_cases)
            files_by_batch[batch] = set(files)
    except (TypeError, ValueError, KeyError) as exc:
        return {"ok": False, "error": f"覆盖率清单批次字段无效: {exc}"}

    navigation_by_batch: dict[int, dict] = {}
    navigation_problems: dict[int, list[str]] = {}
    if cov.get("map_receipts_required") is True:
        for batch in expected_by_batch:
            meta_path = out_dir / f"repo_map_{batch}.meta.json"
            map_path = out_dir / f"repo_map_{batch}.md"
            batch_path = out_dir / f"hunt_batch_{batch}.json"
            meta = _load_json(meta_path)
            if not isinstance(meta, dict) or "__error__" in meta:
                navigation_problems.setdefault(batch, []).append("缺失或无效的 repo_map 导航回执")
                continue
            navigation_by_batch[batch] = meta
            if meta.get("schema_version") != 2:
                navigation_problems.setdefault(batch, []).append("repo_map 回执 schema 缺失或过旧")
            if meta.get("backend") != "treesitter" or meta.get("degraded") is not False:
                navigation_problems.setdefault(batch, []).append(
                    f"导航后端降级: {meta.get('backend', 'unknown')}"
                )
            files_not_indexed = meta.get("files_not_indexed", {})
            if not isinstance(files_not_indexed, dict):
                navigation_problems.setdefault(batch, []).append("repo_map 未提供合法 files_not_indexed 回执")
            elif files_not_indexed:
                navigation_problems.setdefault(batch, []).append(
                    "导航索引漏文件: " + ", ".join(sorted(files_not_indexed))
                )
            if type(meta.get("map_truncated")) is not bool:
                navigation_problems.setdefault(batch, []).append("repo_map 未明确声明是否截断")
            elif meta.get("map_truncated") is True:
                navigation_problems.setdefault(batch, []).append(
                    "repo_map 达到 token 预算并发生截断；提高 --budget 后重建"
                )
            try:
                current_batch_hash = hashlib.sha256(batch_path.read_bytes()).hexdigest()
                current_map_hash = hashlib.sha256(map_path.read_bytes()).hexdigest()
            except OSError:
                navigation_problems.setdefault(batch, []).append("repo_map 或 hunt_batch 文件不可读")
                continue
            if meta.get("batch_sha256") != current_batch_hash:
                navigation_problems.setdefault(batch, []).append("repo_map 回执绑定的 hunt_batch 已变化")
            if meta.get("map_sha256") != current_map_hash:
                navigation_problems.setdefault(batch, []).append("repo_map 回执绑定的地图已变化")

    samples_by_batch: dict[int, set[int]] = {}
    covered_by_batch: dict[int, set[str]] = {}
    sample_problems: dict[int, list[str]] = {}
    bad_results: list[str] = []
    duplicate_samples: list[str] = []
    seen_samples: set[tuple[int, int]] = set()

    for result_path in sorted(out_dir.glob("hunt_result_*.json")):
        obj = _load_json(result_path)
        candidates = obj.get("candidates") if isinstance(obj, dict) else None
        perspectives = obj.get("perspectives_covered") if isinstance(obj, dict) else None
        cases_checked = obj.get("case_ids_checked", []) if isinstance(obj, dict) else None
        if (
            not isinstance(obj, dict) or "batch" not in obj or "sample" not in obj
            or "__error__" in obj or not isinstance(candidates, list)
            or not all(isinstance(x, dict) for x in candidates)
            or not isinstance(perspectives, list)
            or not all(isinstance(x, str) for x in perspectives)
            or not isinstance(cases_checked, list)
            or not all(isinstance(x, str) for x in cases_checked)
            or type(obj.get("batch")) is not int
            or type(obj.get("sample")) is not int
        ):
            bad_results.append(result_path.name)
            continue
        try:
            batch, sample = int(obj["batch"]), int(obj["sample"])
        except (TypeError, ValueError):
            bad_results.append(result_path.name)
            continue
        filename_match = re.fullmatch(r"hunt_result_(\d+)_(\d+)\.json", result_path.name)
        if not filename_match or (batch, sample) != tuple(map(int, filename_match.groups())):
            bad_results.append(result_path.name)
            continue
        key = (batch, sample)
        if key in seen_samples:
            duplicate_samples.append(f"batch={batch},sample={sample}")
            continue
        seen_samples.add(key)
        samples_by_batch.setdefault(batch, set()).add(sample)
        covered_by_batch.setdefault(batch, set()).update(perspectives)
        if batch not in expected_by_batch:
            continue
        problems: list[str] = []
        missing_perspectives = expected_by_batch[batch] - set(perspectives)
        if missing_perspectives:
            problems.append("漏视角: " + ", ".join(sorted(missing_perspectives)))
        missing_cases = expected_cases_by_batch.get(batch, set()) - set(cases_checked)
        if missing_cases:
            problems.append("漏 case: " + ", ".join(sorted(missing_cases)))
        problems.extend(_validate_case_assessments(
            obj,
            expected_cases_by_batch.get(batch, set()),
            files_by_batch.get(batch, set()),
            repo_root,
        ))
        problems.extend(_validate_file_reads(
            obj.get("files_reviewed"), files_by_batch.get(batch, set()), repo_root,
        ))
        if problems:
            sample_problems.setdefault(batch, []).extend(
                f"sample {sample}: {problem}" for problem in problems
            )

    batches: list[dict] = []
    all_ok = True
    for batch in sorted(expected_by_batch):
        samples = samples_by_batch.get(batch, set())
        problems = list(navigation_problems.get(batch, [])) + list(sample_problems.get(batch, []))
        if len(samples) < min_samples:
            problems.append(f"完整样本不足: {len(samples)} < {min_samples}")
        ok = not problems
        all_ok = all_ok and ok
        expected = expected_by_batch[batch]
        covered = covered_by_batch.get(batch, set())
        batches.append({
            "batch": batch,
            "expected": sorted(expected),
            "covered": sorted(covered),
            "missing": sorted(expected - covered),
            "cases_expected": sorted(expected_cases_by_batch.get(batch, set())),
            "files_expected": sorted(files_by_batch.get(batch, set())),
            "samples": len(samples),
            "results": len(samples),
            "ok": ok,
            "problems": problems,
            "navigation": navigation_by_batch.get(batch),
        })

    stray_results = sorted(set(samples_by_batch) - set(expected_by_batch))
    return {
        "schema_version": cov.get("schema_version", 2),
        "coverage_evidence": "file-hash-line-range-receipt",
        "ok": all_ok and not bad_results and not stray_results and not duplicate_samples,
        "min_samples": min_samples,
        "batches_total": len(expected_by_batch),
        "batches": batches,
        "stray_attest_batches": [],
        "stray_result_batches": stray_results,
        "unparseable_attest": [],
        "unparseable_results": bad_results,
        "duplicate_samples": duplicate_samples,
        "navigation_receipts_required": cov.get("map_receipts_required") is True,
    }


def check(
    out_dir: Path, coverage_path: Path, min_samples: int, repo_root: Path | None = None,
) -> dict:
    cov = _load_json(coverage_path)
    if not isinstance(cov, dict) or "batches_detail" not in cov:
        return {"ok": False, "error": f"覆盖率清单无效或缺 batches_detail: {coverage_path}"}

    raw_schema_version = cov.get("schema_version", 1)
    if type(raw_schema_version) is not int:
        return {"ok": False, "error": "覆盖率清单 schema_version 无效"}
    schema_version = raw_schema_version

    if schema_version > 3:
        return {"ok": False, "error": f"不支持未来 hunt_coverage schema_version={schema_version}"}
    if schema_version == 3:
        plan_problems = _validate_v3_plan(out_dir, cov, (repo_root or out_dir).resolve())
        if plan_problems:
            return {
                "schema_version": 3,
                "ok": False,
                "error": "Hunter 批次计划与当前 scope/源码不一致",
                "plan_integrity_problems": plan_problems,
            }
    if schema_version >= 2:
        return _check_v2(out_dir, cov, min_samples, (repo_root or out_dir).resolve())

    try:
        expected_by_batch: dict[int, set[str]] = {
            int(b["batch"]): set(b.get("expected_perspectives", []))
            for b in cov.get("batches_detail", [])
            if isinstance(b, dict)
        }
    except (TypeError, ValueError, KeyError) as exc:
        return {"ok": False, "error": f"覆盖率清单批次字段无效: {exc}"}

    # 汇总回执（每份一个 (batch,sample)）
    covered_by_batch: dict[int, set[str]] = {}
    samples_by_batch: dict[int, int] = {}
    bad_attest: list[str] = []
    for ap in sorted(out_dir.glob("hunt_attest_*.json")):
        obj = _load_json(ap)
        perspectives = obj.get("perspectives_covered") if isinstance(obj, dict) else None
        if (
            not isinstance(obj, dict) or "batch" not in obj or "__error__" in obj
            or not isinstance(perspectives, list)
            or not all(isinstance(x, str) for x in perspectives)
            or type(obj.get("batch")) is not int
        ):
            bad_attest.append(ap.name)
            continue
        try:
            b = int(obj["batch"])
        except (TypeError, ValueError):
            bad_attest.append(ap.name)
            continue
        covered_by_batch.setdefault(b, set()).update(perspectives)
        samples_by_batch[b] = samples_by_batch.get(b, 0) + 1

    result_samples_by_batch: dict[int, int] = {}
    bad_results: list[str] = []
    for rp in sorted(out_dir.glob("hunt_result_*.json")):
        obj = _load_json(rp)
        candidates = obj.get("candidates") if isinstance(obj, dict) else None
        if (
            not isinstance(obj, dict) or "batch" not in obj or "__error__" in obj
            or not isinstance(candidates, list)
            or not all(isinstance(x, dict) for x in candidates)
            or type(obj.get("batch")) is not int
        ):
            bad_results.append(rp.name)
            continue
        try:
            b = int(obj["batch"])
        except (TypeError, ValueError):
            bad_results.append(rp.name)
            continue
        result_samples_by_batch[b] = result_samples_by_batch.get(b, 0) + 1

    batches: list[dict] = []
    all_ok = True
    for b in sorted(expected_by_batch):
        expected = expected_by_batch[b]
        covered = covered_by_batch.get(b, set())
        n_samples = samples_by_batch.get(b, 0)
        n_results = result_samples_by_batch.get(b, 0)
        missing = sorted(expected - covered)
        problems: list[str] = []
        if n_samples == 0:
            problems.append("无回执（hunter 未上报覆盖）")
        if n_results == 0:
            problems.append("无候选结果文件（即使没有疑点也必须写 candidates=[]）")
        if missing:
            problems.append("漏视角: " + ", ".join(missing))
        if 0 < n_samples < min_samples:
            problems.append(f"采样不足: {n_samples} < {min_samples}")
        if 0 < n_results < min_samples:
            problems.append(f"结果采样不足: {n_results} < {min_samples}")
        if n_samples != n_results:
            problems.append(f"结果/回执数量不一致: {n_results} != {n_samples}")
        ok = not problems
        all_ok = all_ok and ok
        batches.append({
            "batch": b,
            "expected": sorted(expected),
            "covered": sorted(covered),
            "missing": missing,
            "samples": n_samples,
            "results": n_results,
            "ok": ok,
            "problems": problems,
        })

    # 指向不存在批次的游离回执
    stray = sorted(set(covered_by_batch) - set(expected_by_batch))
    stray_results = sorted(set(result_samples_by_batch) - set(expected_by_batch))

    return {
        "ok": all_ok and not bad_attest and not bad_results and not stray and not stray_results,
        "min_samples": min_samples,
        "batches_total": len(expected_by_batch),
        "batches": batches,
        "stray_attest_batches": stray,
        "stray_result_batches": stray_results,
        "unparseable_attest": bad_attest,
        "unparseable_results": bad_results,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--repo-root", default=".", help="被扫描仓库根目录（默认 .）")
    ap.add_argument("--out-dir", default=".scan/tmp", help="结果与清单目录（默认 .scan/tmp）")
    ap.add_argument(
        "--coverage", default=None,
        help="覆盖率清单路径（默认 <out-dir>/hunt_coverage.json）",
    )
    ap.add_argument(
        "--min-samples", type=int, default=1,
        help="每批期望独立样本数（= hunt_samples；>1 时核对多采样真的跑够次数）",
    )
    args = ap.parse_args()

    if args.min_samples < 1:
        print(json.dumps({"ok": False, "error": "min-samples 必须 >= 1"}, ensure_ascii=False))
        return 1

    repo_root = Path(args.repo_root).resolve()
    try:
        out_dir = resolve_cli_path(repo_root, args.out_dir, label="hunter coverage output directory")
        coverage_path = (
            resolve_cli_path(repo_root, args.coverage, label="hunter coverage input")
            if args.coverage else out_dir / "hunt_coverage.json"
        )
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1

    if not coverage_path.is_file():
        print(json.dumps(
            {"ok": False, "error": f"覆盖率清单不存在: {coverage_path}（先跑 build_hunt_batches.py）"},
            ensure_ascii=False,
        ))
        return 1

    result = check(out_dir, coverage_path, args.min_samples, repo_root=repo_root)
    (out_dir / "hunt_perspective_coverage.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # stderr 人类可读
    if result.get("error"):
        print(f"[check_hunt_coverage] ❌ {result['error']}", file=sys.stderr)
    else:
        bad = [b for b in result["batches"] if not b["ok"]]
        if result["ok"]:
            print(
                f"[check_hunt_coverage] ✅ {result['batches_total']} 批次文件与视角全部覆盖",
                file=sys.stderr,
            )
        else:
            print(
                f"[check_hunt_coverage] ❌ {len(bad)}/{result['batches_total']} 批次文件或视角校验失败：",
                file=sys.stderr,
            )
            for b in bad:
                print(f"   • batch {b['batch']}: {'; '.join(b['problems'])}", file=sys.stderr)
        if result["unparseable_attest"]:
            print(f"   ⚠ 无法解析的回执: {', '.join(result['unparseable_attest'])}", file=sys.stderr)
        if result["unparseable_results"]:
            print(f"   ⚠ 无法解析的结果: {', '.join(result['unparseable_results'])}", file=sys.stderr)
        if result["stray_attest_batches"] or result["stray_result_batches"]:
            print("   ⚠ 存在指向未知批次的游离结果/回执", file=sys.stderr)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
