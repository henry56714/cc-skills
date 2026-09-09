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

schema v2 不再维护与结果重复的 `hunt_attest_*.json`。旧 schema v1 仍兼容原回执。

仅用 Python 标准库。读取仓库文件并只在 .scan/tmp 写 hunt_perspective_coverage.json。

退出码：0 = 文件证据与视角全部覆盖；1 = 文件/视角/采样/输入校验失败。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


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
        if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
            return False
        normalized.append((start, min(end, line_count)))
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
        if item.get("line_count") != line_count:
            problems.append(f"文件行数不匹配: {rel}")
        if not _ranges_cover(item.get("ranges"), line_count):
            problems.append(f"读取范围未覆盖完整文件: {rel}")
    return problems


def _check_v2(
    out_dir: Path, cov: dict, min_samples: int, repo_root: Path,
) -> dict:
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
        problems = list(sample_problems.get(batch, []))
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
        })

    stray_results = sorted(set(samples_by_batch) - set(expected_by_batch))
    return {
        "schema_version": 2,
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
    }


def check(
    out_dir: Path, coverage_path: Path, min_samples: int, repo_root: Path | None = None,
) -> dict:
    cov = _load_json(coverage_path)
    if not isinstance(cov, dict) or "batches_detail" not in cov:
        return {"ok": False, "error": f"覆盖率清单无效或缺 batches_detail: {coverage_path}"}

    try:
        schema_version = int(cov.get("schema_version", 1))
    except (TypeError, ValueError):
        return {"ok": False, "error": "覆盖率清单 schema_version 无效"}

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
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo_root / out_dir
    coverage_path = Path(args.coverage) if args.coverage else out_dir / "hunt_coverage.json"
    if not coverage_path.is_absolute():
        coverage_path = repo_root / coverage_path

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
