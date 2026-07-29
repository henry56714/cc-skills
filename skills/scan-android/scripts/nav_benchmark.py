#!/usr/bin/env python3
"""
nav_benchmark.py — 跨文件调用导航后端的「地面真值」基准评测器。

为什么有它：导航后端不应靠单个案例拍板取舍。本工具用**人工核验过的
ground-truth 调用集**，对每个可用后端量化 precision / recall / 延迟，让"用谁做默认后端"由数据决定，
而不是再凭单一例子。

它不是扫描流程的一部分（不在 SKILL.md 工作流里），是独立的评测/选型工具，仅读源码、只写 --out 目录。

后端是**可插拔**的（见 BACKENDS 注册表）：
  - source-nav  : 纯标准库源码导航（始终可用，兜底）—— scripts/source_nav.py
  - treesitter  : tree-sitter 语法级导航 —— scripts/repo_map.py

基准文件格式（JSON，见 --help 末尾或 benchmarks/*.json）：
  {
    "name": "...", "repo_hint": "/abs/path",
    "symbols": [
      {"symbol": "Class#method", "lang": "java|kotlin",
       "note": "为什么选它（precision 压测 / recall 用例 …）",
       "definition": [{"file": "<repo-rel>", "line": 121}],
       "callers":    [{"file": "<repo-rel>", "line": 62}, ...]}   # 调用点（call-site）的 file:line
    ]
  }

仅用 Python 标准库。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SKILL_DIR = Path(__file__).resolve().parent
SCAN_TOOLS = Path(os.environ.get("SCAN_ANDROID_TOOLS_DIR", os.path.expanduser("~/.scan-android/tools")))
REPOMAP_VENV = Path(os.environ.get("SCAN_ANDROID_REPOMAP_VENV", os.path.expanduser("~/.scan-android/repomap-venv")))


# ----------------------------------------------------------------------------
# 工具：路径归一 / 集合 / 指标
# ----------------------------------------------------------------------------

def repo_rel(repo: Path, raw: str) -> str:
    """把后端返回的文件路径归一为 repo 相对 posix 路径。"""
    raw = (raw or "").strip()
    if not raw:
        return ""
    p = Path(raw)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(repo).as_posix()
        except ValueError:
            return p.as_posix()
    return Path(raw.lstrip("./")).as_posix()


def to_pairs(items: list[dict[str, Any]], repo: Path) -> set[tuple[str, int]]:
    """[{file,line}] -> {(relfile, line)}。"""
    out: set[tuple[str, int]] = set()
    for it in items or []:
        f = repo_rel(repo, str(it.get("file", "")))
        ln = it.get("line")
        if f and isinstance(ln, int):
            out.add((f, ln))
    return out


def score(returned: set[tuple[str, int]], truth: set[tuple[str, int]]) -> dict[str, Any]:
    tp = len(returned & truth)
    fp = len(returned - truth)
    fn = len(truth - returned)
    prec = (tp / (tp + fp)) if (tp + fp) else None        # 无返回 -> precision 未定义
    rec = (tp / (tp + fn)) if (tp + fn) else 1.0          # 无真值 -> recall 视为 1
    files_returned = {f for f, _ in returned}
    files_truth = {f for f, _ in truth}
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "returned": len(returned), "truth": len(truth),
        "precision": prec, "recall": rec,
        "file_recall": (len(files_returned & files_truth) / len(files_truth)) if files_truth else 1.0,
    }


# ----------------------------------------------------------------------------
# 后端定义（可插拔）。每个后端实现 probe() 与 callers()/definition()。
# ----------------------------------------------------------------------------

class Backend:
    name = "base"

    def probe(self, ctx: dict[str, Any]) -> tuple[bool, str]:
        raise NotImplementedError

    def callers(self, ctx: dict[str, Any], symbol: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def definition(self, ctx: dict[str, Any], symbol: str) -> list[dict[str, Any]]:
        raise NotImplementedError


def _run(cmd: list[str], cwd: Path, timeout: int, env: dict | None = None) -> tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                       timeout=timeout, env=env)
    return p.returncode, p.stdout, p.stderr


class SourceNavBackend(Backend):
    name = "source-nav"

    def _call(self, ctx, action, symbol):
        code, out, err = _run(
            [sys.executable, str(SKILL_DIR / "source_nav.py"),
             "--repo", str(ctx["repo"]), "--action", action, "--symbol", symbol],
            ctx["repo"], ctx["timeout"])
        if code != 0:
            raise RuntimeError(f"source_nav 退出码 {code}: {err.strip()[:200]}")
        return json.loads(out or "[]")

    def probe(self, ctx):
        return (SKILL_DIR / "source_nav.py").exists(), "scripts/source_nav.py"

    def callers(self, ctx, symbol):
        return self._call(ctx, "callers", symbol)

    def definition(self, ctx, symbol):
        return self._call(ctx, "definition", symbol)


class TreeSitterBackend(Backend):
    """tree-sitter 语法级后端。直接调 repo_map.py CLI。

    优先用 repomap venv 的 python（~/.scan-android/repomap-venv/bin/python）以保证
    tree-sitter 可导入；venv 缺失则用当前解释器（repo_map 会自行降级 source-nav——
    此时视为本后端不可用，避免把 source-nav 结果误记到 treesitter 名下）。"""
    name = "treesitter"

    def _py(self) -> str:
        venv_py = REPOMAP_VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        return str(venv_py) if venv_py.exists() else sys.executable

    def _call(self, ctx, action, symbol):
        code, out, err = _run(
            [self._py(), str(SKILL_DIR / "repo_map.py"),
             "--repo", str(ctx["repo"]), "--action", action, "--symbol", symbol],
            ctx["repo"], ctx["timeout"])
        if "改用 source-nav" in err or "回退 source-nav" in err:
            raise RuntimeError("repo_map 降级到 source-nav（tree-sitter 不可用）")
        if code != 0:
            raise RuntimeError(f"repo_map 退出码 {code}: {err.strip()[:200]}")
        return json.loads(out or "[]")

    def probe(self, ctx):
        venv_py = REPOMAP_VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        try:
            import tree_sitter  # noqa: F401
            import tree_sitter_language_pack  # noqa: F401
            return True, "当前解释器可导入 tree-sitter"
        except Exception:
            pass
        if venv_py.exists():
            return True, f"repomap venv: {venv_py}"
        return False, "tree-sitter 不可用（repomap venv 未装）"

    def callers(self, ctx, symbol):
        return self._call(ctx, "callers", symbol)

    def definition(self, ctx, symbol):
        return self._call(ctx, "definition", symbol)


BACKENDS: dict[str, Backend] = {
    b.name: b for b in (SourceNavBackend(), TreeSitterBackend())
}


# ----------------------------------------------------------------------------
# 评测主流程
# ----------------------------------------------------------------------------

def evaluate(ctx: dict[str, Any], bench: dict[str, Any], backends: list[str]) -> dict[str, Any]:
    repo = ctx["repo"]
    symbols = bench.get("symbols", [])
    available: dict[str, str] = {}
    skipped: dict[str, str] = {}
    for name in backends:
        be = BACKENDS[name]
        ok, why = be.probe(ctx)
        (available if ok else skipped)[name] = why

    results: dict[str, Any] = {
        "benchmark": bench.get("name", ""),
        "repo": str(repo),
        "available_backends": available,
        "skipped_backends": skipped,
        "symbols": [],
        "summary": {},
    }

    # 逐符号 × 逐可用后端
    agg: dict[str, dict[str, float]] = {n: {"tp": 0, "ret": 0, "truth": 0, "t": 0.0,
                                            "dtp": 0, "dret": 0, "dtruth": 0} for n in available}
    for sym in symbols:
        s = sym["symbol"]
        gt_callers = to_pairs(sym.get("callers", []), repo)
        gt_defs = to_pairs(sym.get("definition", []), repo)
        row: dict[str, Any] = {"symbol": s, "lang": sym.get("lang", ""),
                               "note": sym.get("note", ""),
                               "gt_callers": len(gt_callers), "gt_defs": len(gt_defs),
                               "backends": {}}
        for name in available:
            be = BACKENDS[name]
            entry: dict[str, Any] = {}
            try:
                t0 = time.time()
                ret_c = to_pairs(be.callers(ctx, s), repo)
                ret_d = to_pairs(be.definition(ctx, s), repo)
                dt = time.time() - t0
                sc = score(ret_c, gt_callers)
                sd = score(ret_d, gt_defs)
                entry = {"callers": sc, "definition": sd, "seconds": round(dt, 3)}
                a = agg[name]
                a["tp"] += sc["tp"]
                a["ret"] += sc["returned"]
                a["truth"] += sc["truth"]
                a["dtp"] += sd["tp"]
                a["dret"] += sd["returned"]
                a["dtruth"] += sd["truth"]
                a["t"] += dt
            except subprocess.TimeoutExpired:
                entry = {"error": f"超时(>{ctx['timeout']}s)"}
            except Exception as e:  # noqa: BLE001 — 评测器要对单后端失败鲁棒
                entry = {"error": str(e)[:300]}
            row["backends"][name] = entry
        results["symbols"].append(row)

    for name, a in agg.items():
        mp = (a["tp"] / a["ret"]) if a["ret"] else None
        mr = (a["tp"] / a["truth"]) if a["truth"] else None
        dmp = (a["dtp"] / a["dret"]) if a["dret"] else None
        dmr = (a["dtp"] / a["dtruth"]) if a["dtruth"] else None
        results["summary"][name] = {
            "callers_micro_precision": mp, "callers_micro_recall": mr,
            "callers_f1": (2 * mp * mr / (mp + mr)) if (mp and mr) else None,
            "def_micro_precision": dmp, "def_micro_recall": dmr,
            "total_seconds": round(a["t"], 3),
            "tp": a["tp"], "returned": a["ret"], "truth": a["truth"],
        }
    return results


def _pct(x):
    return "—" if x is None else f"{x * 100:.1f}%"


def render_md(r: dict[str, Any]) -> str:
    L = [f"# 导航后端基准评测：{r['benchmark']}", "",
         f"仓库：`{r['repo']}`", ""]
    if r["skipped_backends"]:
        L.append("**未参与的后端：**")
        for n, why in r["skipped_backends"].items():
            L.append(f"- `{n}`：{why}")
        L.append("")
    L += ["## 汇总（micro-averaged，按调用点 file:line 精确匹配）", "",
          "| 后端 | callers 精确率 | callers 召回率 | F1 | 命中/返回/真值 | 定义精确率 | 定义召回率 | 总耗时(s) |",
          "|---|---|---|---|---|---|---|---|"]
    for n, s in r["summary"].items():
        L.append(f"| `{n}` | {_pct(s['callers_micro_precision'])} | {_pct(s['callers_micro_recall'])} | "
                 f"{_pct(s['callers_f1'])} | {s['tp']}/{s['returned']}/{s['truth']} | "
                 f"{_pct(s['def_micro_precision'])} | {_pct(s['def_micro_recall'])} | {s['total_seconds']} |")
    L += ["", "## 逐符号（callers）", "",
          "| 符号 | lang | 用例 | 真值 | " +
          " | ".join(f"`{n}` 返回/命中 (P/R)" for n in r["summary"]) + " |",
          "|---|---|---|---|" + "---|" * len(r["summary"])]
    for row in r["symbols"]:
        cells = []
        for n in r["summary"]:
            e = row["backends"].get(n, {})
            if "error" in e:
                cells.append(f"err: {e['error'][:40]}")
            else:
                c = e["callers"]
                cells.append(f"{c['returned']}/{c['tp']} ({_pct(c['precision'])}/{_pct(c['recall'])})")
        L.append(f"| `{row['symbol']}` | {row['lang']} | {row['note']} | {row['gt_callers']} | "
                 + " | ".join(cells) + " |")
    L.append("")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="跨文件调用导航后端的 ground-truth 基准评测器",
        epilog="基准文件格式见模块 docstring；后端：" + ", ".join(BACKENDS))
    ap.add_argument("--repo", required=True, help="被评测的工程根（cwd 形式的绝对路径）")
    ap.add_argument("--benchmark", required=True, help="ground-truth JSON 文件")
    ap.add_argument("--backends", default="all",
                    help="逗号分隔；'all'=全部注册后端。可选：" + ",".join(BACKENDS))
    ap.add_argument("--out", default=None, help="报告输出目录（默认 <repo>/.scan/nav_bench）")
    ap.add_argument("--timeout", type=int, default=300, help="每次后端调用超时秒数")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"repo 不存在: {repo}", file=sys.stderr)
        return 2
    bench = json.loads(Path(args.benchmark).read_text(encoding="utf-8"))
    out = Path(args.out) if args.out else repo / ".scan" / "nav_bench"
    out.mkdir(parents=True, exist_ok=True)

    names = list(BACKENDS) if args.backends == "all" else [b.strip() for b in args.backends.split(",") if b.strip()]
    for n in names:
        if n not in BACKENDS:
            print(f"未知后端: {n}（可选: {', '.join(BACKENDS)}）", file=sys.stderr)
            return 2

    ctx = {"repo": repo, "out": out, "timeout": args.timeout}
    results = evaluate(ctx, bench, names)

    (out / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    md = render_md(results)
    (out / "report.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"\n[nav_benchmark] 详细结果: {out/'results.json'}  报告: {out/'report.md'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
