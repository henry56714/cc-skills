#!/usr/bin/env python3
"""
引擎编排器 —— v2 架构的候选生成入口（替代 v1 的 prefilter.py）。

注册可用的引擎 adapter，逐个运行，把各引擎产出的候选归一化为统一契约后聚合输出。
后续阶段只需新增 adapter 并在 _REGISTRY 注册，
本编排器与下游管线（LLM 验证 / 去重 / 报告）均无需改动。
（注：tree-sitter 是 verifier 的调用/类型导航后端，不是候选生成引擎，见 nav_tools.py。）

用法:
    run_engines.py --scope-files PATH [--rules-dir DIR]
                   [--max-per-rule N] [--repo-root DIR] [--engines CSV|auto]

--engines:
    auto（默认）= 运行所有"可用"的已注册引擎
    CSV         = 仅运行指定引擎（如 semgrep,pmd）；未选和不可用的引擎
                  都会显式记为覆盖缺口，不会伪装成 complete

引擎缺失、超时或执行失败会记录为 incomplete，不丢弃其他引擎已经产出的候选。
Lint 会执行目标仓库的 Gradle 逻辑，默认禁用，只有显式授权后才运行。

输出 JSON 到 stdout：
    {
      "engines_used": ["semgrep", "detekt", "pmd"],
      "engine_stats": [ {"engine": "semgrep", "rules_run": N, "candidates": N}, ... ],
      "engines_skipped": [{"engine": "...", "reason": "..."}],
      "rules_run": N,
      "rules_total": N,
      "candidates": [ <归一化 Candidate>, ... ],
      "notes": [ {"rule_id"|"engine": ..., "note": ...}, ... ]
    }

engine_stats 逐引擎给出本次"命中规则种类数"与"产出候选数"，供报告头展示。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adapters.base import EngineAdapter, InstallationError, ScanContext
from adapters.semgrep_adapter import SemgrepAdapter
from adapters.detekt_adapter import DetektAdapter
from adapters.pmd_adapter import PMDAdapter
from adapters.lint_adapter import LintAdapter
from detect_project import detect_project
from lib_scan import (
    atomic_write_json, effective_excluded_engines, resolve_cli_path,
)

# 已注册引擎，按"广度→深度"优先级排列。规则全部来自社区库/引擎自带。
# - P1: semgrep（社区 registry + 本地补充，含 taint 模式）、detekt（Kotlin）、pmd（Java）、lint（Android）
# 本 skill 只扫描源码工程，不注册 APK/AAB 引擎。
# 注：跨文件**调用/类型**导航由 tree-sitter 语法索引提供，见 nav_tools.py，
#     供 verifier 取证调用链——它不是候选生成引擎，故不在本注册表内。
#     深层污点/数据流由 Semgrep taint + AI 狩猎（rules/ai/）覆盖。
_REGISTRY: list[EngineAdapter] = [
    SemgrepAdapter(),   # P1: 广度（含社区 registry 包 + taint 模式）
    DetektAdapter(),    # P1: Kotlin 专项
    PMDAdapter(),       # P1: Java 专项（errorprone / 多线程 / 性能）
    LintAdapter(),      # P1: Android Lint
]

# 规则目录相对**本脚本自身**定位（scripts/ 的同级 rules/），与安装位置、cwd 无关。
_DEFAULT_RULES_DIR = str(Path(__file__).resolve().parent.parent / "rules")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope-files", required=True)
    ap.add_argument("--rules-dir", default=_DEFAULT_RULES_DIR)
    ap.add_argument("--max-per-rule", type=int, default=0,
                    help="单规则候选上限；0=不截断（默认）")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--engines", default="auto", help='auto 或 CSV，如 semgrep,pmd')
    ap.add_argument("--output", default=None, help="同时将完整 JSON 原子写入此路径")
    ap.add_argument(
        "--allow-build-execution", action="store_true",
        help="允许执行仓库的 Gradle/Lint 构建逻辑；仅对可信仓库使用",
    )
    ap.add_argument(
        "--allow-network-rules", action="store_true",
        help="允许 Semgrep 联网获取固定 registry 规则包；受信配置只能选择 pack，不能授权联网",
    )
    ap.add_argument(
        "--trust-project-config", action="store_true",
        help="允许已审阅的仓库配置改变引擎/任务策略；不授予构建或联网能力",
    )
    ap.add_argument(
        "--install-missing", action="store_true",
        help="显式允许联网并将缺失引擎安装到 ~/.scan-android",
    )
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()
    safe_output: str | None = None
    try:
        resolve_cli_path(repo, ".scan/tmp", label="scan working directory")
        scope_path = resolve_cli_path(repo, args.scope_files, label="scope file")
        if args.output:
            safe_output = str(resolve_cli_path(repo, args.output, label="engine output"))
            args.output = safe_output
        scope_files = _read_scope(str(scope_path), repo)
        scope_snapshot_before = _scope_snapshot(repo, scope_files)
    except (OSError, ValueError) as exc:
        _emit({"status": "incomplete", "scan_complete": False, "error": str(exc)}, safe_output)
        return 2

    _, declared_config = _load_engine_config(repo)
    config = declared_config if args.trust_project_config else {}
    excluded = effective_excluded_engines(config)
    detect_info = detect_project(repo, trust_project_config=args.trust_project_config)
    ctx = ScanContext(
        repo=repo,
        scope_files=scope_files,
        rules_dir=Path(args.rules_dir),
        max_per_rule=args.max_per_rule,
        detect_info=detect_info,
        excluded_engines=excluded,
        # These are invocation capabilities.  Never allow untrusted repository
        # configuration to grant execution or network access to itself.
        allow_build_execution=args.allow_build_execution,
        allow_network_rules=args.allow_network_rules,
        trust_project_config=args.trust_project_config,
        allow_installation=args.install_missing,
    )
    _invalidate_downstream(repo)

    requested = [s.strip() for s in args.engines.split(",") if s.strip()]
    known = {a.name for a in _REGISTRY}
    if args.engines.strip().lower() != "auto" and not requested:
        _emit({
            "status": "incomplete", "scan_complete": False,
            "error": "--engines 不能为空", "available_engines": sorted(known),
        }, args.output)
        return 2
    unknown = [] if args.engines.strip().lower() == "auto" else [n for n in requested if n not in known]
    if unknown:
        _emit({
            "status": "incomplete", "scan_complete": False,
            "error": f"未知引擎: {', '.join(unknown)}", "available_engines": sorted(known),
        }, args.output)
        return 2
    selected = _select_engines(args.engines)
    selected_names = {adapter.name for adapter in selected}

    engines_used: list[str] = []
    engines_skipped: list[dict] = []
    engine_stats: list[dict] = []
    all_candidates: list[dict] = []
    all_notes: list[dict] = []
    if declared_config.get("__config_error__"):
        all_notes.append({
            "engine": "config",
            "note": f"配置无效，已使用安全默认值: {declared_config['__config_error__']}",
        })
    if declared_config and not args.trust_project_config and not declared_config.get("__config_error__"):
        all_notes.append({
            "engine": "config",
            "note": "目标仓库扫描策略默认不受信任，已忽略 excluded_engines/extra_excludes/lint_tasks 等配置",
        })
    if declared_config.get("allow_gradle_execution") is True and not args.allow_build_execution:
        all_notes.append({
            "engine": "config",
            "note": "忽略仓库 config.allow_gradle_execution；仅命令行 --allow-build-execution 可授权执行目标仓库代码",
        })
    if declared_config.get("semgrep_use_registry") is True and not args.allow_network_rules:
        all_notes.append({
            "engine": "config",
            "note": "仓库请求了 Semgrep registry，但未获调用方 --allow-network-rules 授权；保持离线本地规则模式",
        })
    rules_run = 0
    rules_total = 0

    for engine, reason in _unselected_engine_gaps(selected_names, set(excluded)):
        engines_skipped.append({"engine": engine, "reason": reason})
        engine_stats.append({
            "engine": engine,
            "status": "skipped",
            "rules_run": 0,
            "rules_triggered": 0,
            "rules_configured": None,
            "candidates": 0,
            "truncated": 0,
            "reason": reason,
        })

    for adapter in selected:
        if adapter.name in ctx.excluded_engines:
            engines_skipped.append({"engine": adapter.name, "reason": "excluded_engines 配置排除"})
            engine_stats.append({"engine": adapter.name, "status": "skipped", "rules_run": 0,
                                 "candidates": 0, "truncated": 0,
                                 "reason": "excluded_engines 配置排除"})
            continue
        try:
            available, reason = adapter.is_available(ctx)
        except InstallationError as e:
            reason = f"安装失败: {e}"
            engines_skipped.append({"engine": adapter.name, "reason": reason})
            engine_stats.append({"engine": adapter.name, "status": "failed", "rules_run": 0,
                                 "candidates": 0, "truncated": 0, "reason": reason})
            all_notes.append({"engine": adapter.name, "note": reason})
            continue
        except Exception as e:
            reason = f"可用性检查异常: {type(e).__name__}: {e}"
            engines_skipped.append({"engine": adapter.name, "reason": reason})
            engine_stats.append({"engine": adapter.name, "status": "failed", "rules_run": 0,
                                 "candidates": 0, "truncated": 0, "reason": reason})
            all_notes.append({"engine": adapter.name, "note": reason})
            continue
        if not available:
            if adapter.name == "lint" and not ctx.allow_build_execution:
                engines_skipped.append({"engine": adapter.name, "reason": reason})
                engine_stats.append({
                    "engine": adapter.name, "status": "skipped", "rules_run": 0,
                    "rules_triggered": 0, "rules_configured": None,
                    "candidates": 0, "truncated": 0, "reason": reason,
                })
                continue
            engines_skipped.append({"engine": adapter.name, "reason": reason})
            engine_stats.append({"engine": adapter.name, "status": "failed", "rules_run": 0,
                                 "candidates": 0, "truncated": 0, "reason": reason})
            continue
        try:
            res = adapter.run(ctx)
        except Exception as e:
            reason = f"引擎执行异常: {type(e).__name__}: {e}"
            engines_skipped.append({"engine": adapter.name, "reason": reason})
            engine_stats.append({"engine": adapter.name, "status": "failed", "rules_run": 0,
                                 "candidates": 0, "truncated": 0, "reason": reason})
            all_notes.append({"engine": adapter.name, "note": reason})
            continue
        if res.status not in {"complete", "partial", "failed", "skipped", "not_applicable"}:
            invalid_status = res.status
            res.status = "failed"
            res.notes.append({
                "engine": adapter.name,
                "note": f"引擎返回未知状态 {invalid_status!r}；已按 failed 处理",
            })
        raw_candidate_count = len(res.candidates)
        res.candidates = _dedupe_candidates(res.candidates)
        if len(res.candidates) != raw_candidate_count:
            res.notes.append({
                "engine": adapter.name,
                "note": f"合并 {raw_candidate_count - len(res.candidates)} 条同引擎同规则同位置的重叠候选",
            })
        if not res.available:
            engines_skipped.append({"engine": adapter.name, "reason": res.unavailable_reason})
            engine_stats.append({"engine": adapter.name, "status": "failed", "rules_run": res.rules_run,
                                 "candidates": len(res.candidates), "truncated": res.truncated,
                                 "reason": res.unavailable_reason})
            all_candidates.extend(c.to_dict() for c in res.candidates)
            all_notes.extend(res.notes)
            continue
        if res.status in ("complete", "partial"):
            engines_used.append(adapter.name)
        stat = {
            "engine": adapter.name,
            "status": res.status,
            "rules_run": res.rules_run,      # 兼容字段：本次触发的规则种类数
            "rules_triggered": res.rules_run,
            "rules_configured": res.rules_total or None,
            "candidates": len(res.candidates),
            "truncated": res.truncated,
            "suppressed": res.suppressed,
        }
        if res.suppression_summary:
            stat["suppression_summary"] = res.suppression_summary
        if res.status in ("partial", "failed"):
            reason_parts = [
                str(note.get("note", "")).strip()
                for note in res.notes if isinstance(note, dict) and note.get("note")
            ]
            reason = res.unavailable_reason or "; ".join(reason_parts[-3:])
            if reason:
                stat["reason"] = reason[:1000]
        engine_stats.append(stat)
        all_candidates.extend(c.to_dict() for c in res.candidates)
        all_notes.extend(res.notes)
        rules_run += res.rules_run
        # 各引擎规则命名空间彼此独立，汇总应求和；取最大值会低报覆盖量。
        rules_total += res.rules_total

    scope_snapshot_error = ""
    try:
        scope_snapshot_after = _scope_snapshot(repo, scope_files)
    except OSError as exc:
        scope_snapshot_after = []
        scope_snapshot_error = str(exc)
    scope_changed = bool(scope_snapshot_error) or scope_snapshot_before != scope_snapshot_after
    if scope_changed:
        engine_stats.append({
            "engine": "scope_integrity",
            "status": "failed",
            "rules_run": 0,
            "rules_triggered": 0,
            "rules_configured": 0,
            "candidates": 0,
            "truncated": 0,
            "reason": (
                "作用域源码在工具引擎运行期间发生变化；结果不能绑定到单一版本"
                + (f": {scope_snapshot_error}" if scope_snapshot_error else "")
            ),
        })
        all_notes.append({
            "engine": "scope_integrity",
            "note": "作用域源码在工具引擎运行期间发生变化；请停止写入后重跑",
        })

    incomplete = sorted(
        str(s.get("engine")) for s in engine_stats
        if s.get("status") in ("partial", "failed")
    )
    coverage_gaps = [
        {"engine": s.get("engine"), "reason": s.get("reason", "skipped")}
        for s in engine_stats if s.get("status") == "skipped"
    ]
    overall_status = _overall_status(engine_stats)
    out = {
        "status": overall_status,
        "scan_complete": overall_status == "complete",
        "configured_complete": not incomplete,
        "coverage_complete": not incomplete and not coverage_gaps,
        "incomplete_engines": incomplete,
        "coverage_gaps": coverage_gaps,
        "engines_used": engines_used,
        "engine_stats": engine_stats,
        "engines_skipped": engines_skipped,
        "rules_run": rules_run,
        "rules_total": rules_total,
        "candidates": all_candidates,
        "scope_snapshot": scope_snapshot_before,
        "scope_changed_during_scan": scope_changed,
        "config_fingerprint": hashlib.sha256(
            json.dumps(
                detect_info.get("config", {}), sort_keys=True, ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest(),
        "config_trusted": bool(detect_info.get("config_trusted")),
        "effective_excluded_engines": excluded,
        "invocation_capabilities": {
            "build_execution": bool(args.allow_build_execution),
            "network_rules": bool(args.allow_network_rules),
            "install_missing": bool(args.install_missing),
        },
    }
    if all_notes:
        out["notes"] = all_notes
    _emit(out, args.output)
    return 0


def _emit(payload: dict, output: str | None) -> None:
    if output:
        atomic_write_json(output, payload)
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def _invalidate_downstream(repo: Path) -> None:
    """A new engine run makes previous verifier/merge receipts stale."""
    tmp = repo / ".scan" / "tmp"
    for pattern in ("verify_batch_*.json", "verified_batch_*.json"):
        for path in tmp.glob(pattern):
            path.unlink()
    for name in ("verify_coverage.json", "merge_receipt.json"):
        path = tmp / name
        if path.exists():
            path.unlink()


def _select_engines(spec: str) -> list[EngineAdapter]:
    if spec.strip().lower() == "auto":
        return list(_REGISTRY)
    # Preserve caller order but do not run an adapter twice when a CSV repeats
    # a name.  Duplicate stats would make the scanner reject its own artifact.
    wanted = list(dict.fromkeys(s.strip() for s in spec.split(",") if s.strip()))
    by_name = {a.name: a for a in _REGISTRY}
    return [by_name[n] for n in wanted if n in by_name]


def _unselected_engine_gaps(
    selected_names: set[str], excluded_names: set[str],
) -> list[tuple[str, str]]:
    gaps: list[tuple[str, str]] = []
    for adapter in _REGISTRY:
        if adapter.name in selected_names:
            continue
        reason = (
            "excluded_engines 配置排除"
            if adapter.name in excluded_names
            else "未被本次 --engines 选择"
        )
        gaps.append((adapter.name, reason))
    return gaps


def _overall_status(engine_stats: list[dict]) -> str:
    statuses = {str(stat.get("status", "complete")) for stat in engine_stats}
    if statuses - {"complete", "partial", "failed", "skipped", "not_applicable"}:
        return "incomplete"
    if statuses & {"partial", "failed"}:
        return "incomplete"
    if "skipped" in statuses:
        return "complete_with_skips"
    return "complete"


def _dedupe_candidates(candidates: list) -> list:
    """合并同引擎、同规则、同位置的重叠匹配，保留证据更丰富者。

    rule_id 是 key 的一部分，因此同一行的不同根因不会被误删。
    """
    best: dict[tuple, object] = {}

    def score(candidate) -> int:
        obj = candidate.to_dict()
        return (
            len(str(obj.get("snippet", "")))
            + len(str(obj.get("message", "")))
            + 4 * len(json.dumps(obj.get("dataflow_path", []), ensure_ascii=False))
            + int(obj.get("end_line", obj.get("line", 0)))
        )

    for candidate in candidates:
        key = (
            candidate.engine,
            candidate.rule_id,
            candidate.file,
            int(candidate.line),
            candidate.category,
        )
        if key not in best or score(candidate) > score(best[key]):
            best[key] = candidate
    return list(best.values())


def _read_scope(path: str, repo: Path) -> list[str]:
    repo = repo.resolve()
    seen: set[str] = set()
    result: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            rel = raw.strip().replace("\\", "/")
            if not rel or rel.startswith("#"):
                continue
            candidate = Path(rel)
            if candidate.is_absolute():
                raise ValueError(f"作用域路径必须是仓库相对路径: {rel}")
            resolved = (repo / candidate).resolve()
            try:
                normalized = resolved.relative_to(repo).as_posix()
            except ValueError as exc:
                raise ValueError(f"作用域路径越出仓库: {rel}") from exc
            if not resolved.is_file():
                raise ValueError(f"作用域文件不存在或不可读: {rel}")
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
    return result


def _scope_snapshot(repo: Path, scope_files: list[str]) -> list[dict]:
    receipts: list[dict] = []
    for rel in scope_files:
        path = repo / rel
        data = path.read_bytes()
        receipts.append({
            "file": rel,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    return receipts


def _load_engine_config(repo: Path) -> tuple[list[str], dict]:
    """从 .scan/config.json 读取 excluded_engines 与其余配置。"""
    cfg: dict = {}
    try:
        config_path = resolve_cli_path(repo, ".scan/config.json", label="scan config")
    except ValueError as exc:
        return [], {"__config_error__": str(exc)}
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                cfg = loaded
            else:
                cfg = {"__config_error__": "top-level JSON must be an object"}
        except Exception as exc:
            cfg = {"__config_error__": str(exc)}

    return effective_excluded_engines(cfg), cfg


if __name__ == "__main__":
    sys.exit(main())
