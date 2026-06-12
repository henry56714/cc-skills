#!/usr/bin/env python3
"""
引擎编排器 —— v2 架构的候选生成入口（替代 v1 的 prefilter.py）。

注册可用的引擎 adapter，逐个运行，把各引擎产出的候选归一化为统一契约后聚合输出。
后续阶段（Semgrep / Joern / CodeQL ...）只需新增 adapter 并在 _REGISTRY 注册，
本编排器与下游管线（LLM 验证 / 去重 / 报告）均无需改动。

用法:
    run_engines.py --scope-files PATH [--rules-dir DIR]
                   [--max-per-rule N] [--repo-root DIR] [--engines CSV|auto]

--engines:
    auto（默认）= 运行所有"可用"的已注册引擎
    CSV         = 仅运行指定引擎（如 regex,semgrep），不可用的会被跳过并记录原因

就绪前提（v3 strict）：
    引擎就绪由 preflight.py 在扫描前强制保证（缺则自动安装，装不上即中断）。
    因此本编排器不再有"降级"概念——所有必需引擎都应已就绪。

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
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adapters.base import EngineAdapter, InstallationError, ScanContext
from adapters.semgrep_adapter import SemgrepAdapter
from adapters.detekt_adapter import DetektAdapter
from adapters.pmd_adapter import PMDAdapter
from adapters.lint_adapter import LintAdapter
from adapters.joern_adapter import JoernAdapter
from adapters.codeql_adapter import CodeQLAdapter
from adapters.mobsf_adapter import MobSFAdapter
from adapters.flowdroid_adapter import FlowDroidAdapter

# 已注册引擎，按"广度→深度"优先级排列。规则全部来自社区库/引擎自带（v3：
# 不再有 regex 引擎——旧 rules/*.md 已退役，其领域知识迁入 rules/ai/）。
# - P1: semgrep（社区 registry + 本地补充）、detekt（Kotlin）、pmd（Java）、lint（Android）
# - P2: joern（CPG 跨文件骨干）
# - P4: codeql / mobsf / flowdroid（opt-in）
_REGISTRY: list[EngineAdapter] = [
    SemgrepAdapter(),   # P1: 广度（含社区 registry 包）
    DetektAdapter(),    # P1: Kotlin 专项
    PMDAdapter(),       # P1: Java 专项（errorprone / 多线程 / 性能）
    LintAdapter(),      # P1: Android Lint
    JoernAdapter(),     # P2: CPG 骨干（深度）
    CodeQLAdapter(),    # P4: opt-in（需 SCAN_ANDROID_ENABLE_CODEQL=1）
    MobSFAdapter(),     # P4: opt-in（需 SCAN_ANDROID_ENABLE_MOBSF=1）
    FlowDroidAdapter(), # P4: opt-in（需 SCAN_ANDROID_ENABLE_FLOWDROID=1）
]

# 规则目录相对**本脚本自身**定位（scripts/ 的同级 rules/），与安装位置、cwd 无关。
_DEFAULT_RULES_DIR = str(Path(__file__).resolve().parent.parent / "rules")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope-files", required=True)
    ap.add_argument("--rules-dir", default=_DEFAULT_RULES_DIR)
    ap.add_argument("--max-per-rule", type=int, default=100)
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--engines", default="auto", help='auto 或 CSV，如 semgrep,pmd')
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()
    scope_files = _read_scope(args.scope_files)

    opt_in, excluded = _load_engine_config(repo)
    ctx = ScanContext(
        repo=repo,
        scope_files=scope_files,
        rules_dir=Path(args.rules_dir),
        max_per_rule=args.max_per_rule,
        opt_in_engines=opt_in,
        excluded_engines=excluded,
    )

    selected = _select_engines(args.engines)

    engines_used: list[str] = []
    engines_skipped: list[dict] = []
    engine_stats: list[dict] = []
    all_candidates: list[dict] = []
    all_notes: list[dict] = []
    rules_run = 0
    rules_total = 0

    for adapter in selected:
        if adapter.name in ctx.excluded_engines:
            engines_skipped.append({"engine": adapter.name, "reason": "excluded_engines 配置排除"})
            continue
        try:
            available, reason = adapter.is_available(ctx)
        except InstallationError as e:
            # 引擎已配置为必需，但安装失败 → 中止整次扫描
            msg = (
                f"\n{'='*60}\n"
                f"[scan-android] 必需引擎安装失败，扫描中止\n"
                f"{'='*60}\n"
                f"{e}\n"
                f"{'='*60}\n"
            )
            print(msg, file=sys.stderr, flush=True)
            # 输出带错误标记的 JSON，让调用方可以解析
            err_out = {
                "engines_used": engines_used,
                "engines_skipped": engines_skipped,
                "rules_run": 0,
                "rules_total": 0,
                "candidates": [],
                "fatal_error": {
                    "engine": adapter.name,
                    "message": str(e),
                },
            }
            json.dump(err_out, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            sys.exit(1)
        if not available:
            engines_skipped.append({"engine": adapter.name, "reason": reason})
            continue
        res = adapter.run(ctx)
        if not res.available:
            engines_skipped.append({"engine": adapter.name, "reason": res.unavailable_reason})
            continue
        engines_used.append(adapter.name)
        engine_stats.append({
            "engine": adapter.name,
            "rules_run": res.rules_run,      # 本次命中的规则种类数
            "candidates": len(res.candidates),
        })
        all_candidates.extend(c.to_dict() for c in res.candidates)
        all_notes.extend(res.notes)
        rules_run += res.rules_run
        rules_total = max(rules_total, res.rules_total)

    out = {
        "engines_used": engines_used,
        "engine_stats": engine_stats,
        "engines_skipped": engines_skipped,
        "rules_run": rules_run,
        "rules_total": rules_total,
        "candidates": all_candidates,
    }
    if all_notes:
        out["notes"] = all_notes
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def _select_engines(spec: str) -> list[EngineAdapter]:
    if spec.strip().lower() == "auto":
        return list(_REGISTRY)
    wanted = [s.strip() for s in spec.split(",") if s.strip()]
    by_name = {a.name: a for a in _REGISTRY}
    return [by_name[n] for n in wanted if n in by_name]


def _read_scope(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def _load_engine_config(repo: Path) -> tuple[list[str], list[str]]:
    """从 .scan/config.json 读取 opt_in_engines / excluded_engines，与环境变量取并集。

    返回 (opt_in_engines, excluded_engines)。
    excluded_engines 优先级高于 opt_in_engines：同时出现时引擎被排除。
    """
    cfg: dict = {}
    config_path = repo / ".scan" / "config.json"
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            pass

    from_config_opt_in = [e.strip() for e in cfg.get("opt_in_engines", []) if e.strip()]
    from_config_excluded = [e.strip() for e in cfg.get("excluded_engines", []) if e.strip()]

    env_map = {
        "SCAN_ANDROID_ENABLE_CODEQL": "codeql",
        "SCAN_ANDROID_ENABLE_MOBSF": "mobsf",
        "SCAN_ANDROID_ENABLE_FLOWDROID": "flowdroid",
    }
    from_env_opt_in = [name for var, name in env_map.items() if os.environ.get(var)]

    def _dedup(items: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for e in items:
            if e not in seen:
                seen.add(e)
                result.append(e)
        return result

    return _dedup(from_config_opt_in + from_env_opt_in), _dedup(from_config_excluded)


if __name__ == "__main__":
    sys.exit(main())
