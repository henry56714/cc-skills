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
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib_scan import atomic_write_json, finding_id, root_cause_id, severity_rank

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


def _needs_origin(category: str) -> bool:
    c = category or ""
    if any(c.startswith(p) for p in ORIGIN_REQUIRED_PREFIXES):
        return True
    return any(s in c for s in ORIGIN_REQUIRED_SUBSTRINGS)


def _has_origin(cand: dict) -> bool:
    return bool(cand.get("dataflow_path")) or bool(cand.get("origin_trace"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
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
    # --commit 仅为兼容旧调用而保留，已忽略（无 ledger 后报告不含 commit/时间）
    ap.add_argument("--commit", default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()

    raw = sys.stdin.read().strip()
    try:
        if args.verified_glob:
            if raw:
                print("--verified-glob 与 stdin 输入不能同时使用", file=sys.stderr)
                return 2
            payload = _load_verified_glob(args.verified_glob, args.verify_coverage)
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
    atomic_write_json(args.findings, {"schema_version": 4, "findings": findings_list})
    atomic_write_json(args.needs_review, {"schema_version": 2, "needs_review": needs_review_list})

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
    print(json.dumps(out, ensure_ascii=False))
    return 0


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


def _load_verified_glob(pattern: str, coverage_path: str) -> dict:
    files = sorted(Path(".").glob(pattern))
    if not files:
        raise ValueError(f"没有 verifier 输出匹配: {pattern}")
    coverage_file = Path(coverage_path)
    if not coverage_file.is_file():
        raise ValueError(f"verifier 覆盖率清单不存在: {coverage_file}")
    coverage = json.loads(coverage_file.read_text(encoding="utf-8"))
    if not isinstance(coverage, dict) or coverage.get("coverage_ok") is not True:
        raise ValueError(f"verifier 覆盖率清单无效或 coverage_ok=false: {coverage_file}")
    batch_files = coverage.get("batch_files")
    if not isinstance(batch_files, list) or not all(isinstance(x, str) for x in batch_files):
        raise ValueError(f"verifier 覆盖率清单缺少合法 batch_files: {coverage_file}")
    if (
        type(coverage.get("candidates_input")) is not int
        or type(coverage.get("candidates_batched")) is not int
        or coverage["candidates_input"] != coverage["candidates_batched"]
        or coverage.get("batches") != len(batch_files)
    ):
        raise ValueError(f"verifier 覆盖率计数不守恒: {coverage_file}")
    expected = {
        Path(raw).resolve().with_name(
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
        input_ids = {
            str(item.get("candidate_id")) for item in input_items
            if isinstance(item, dict) and item.get("candidate_id")
        }
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
            if not isinstance(provenance, list) or not provenance or not all(isinstance(x, dict) for x in provenance):
                raise ValueError(f"verifier 输出缺少 provenance: {path}")
            unknown = set(source_ids) - input_ids
            if unknown:
                raise ValueError(f"verifier 输出引用未知 candidate_id: {path} ids={sorted(unknown)}")
            repeated = emitted_ids & set(source_ids)
            if repeated:
                raise ValueError(f"同一 candidate_id 被输出到多个 finding: {path} ids={sorted(repeated)}")
            emitted_ids.update(source_ids)
        expected_emitted = (
            len(obj.get("confirmed", [])) + len(obj.get("needs_review", []))
            + duplicate_count
        )
        if len(emitted_ids) != expected_emitted:
            raise ValueError(
                f"verifier provenance 数量不守恒: {path} "
                f"emitted_ids={len(emitted_ids)}, expected={expected_emitted}"
            )


if __name__ == "__main__":
    sys.exit(main())
