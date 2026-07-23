#!/usr/bin/env python3
"""
从 .scan/findings.json 渲染 .scan/reports/findings.md。

用法:
    render_report.py [--findings PATH] [--output PATH] [--engines-used CSV]

排序：severity (critical→major→minor→info) → category asc → file asc → line asc。

v3：无状态、无 ledger——报告不含 commit/时间，仅展示本次扫描确认的问题。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib_scan import (
    load_json,
    severity_rank,
)


SEVERITY_LABELS = [
    ("critical", "Critical"),
    ("major", "Major"),
    ("minor", "Minor"),
    ("info", "Info"),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", default=".scan/findings.json")
    ap.add_argument("--output", default=".scan/reports/findings.md")
    ap.add_argument("--engines-used", default=None, help="已使用引擎 CSV（如 semgrep,detekt）；写入报告头")
    ap.add_argument("--engine-stats", default=None,
                    help='每引擎规则/候选数的 JSON（run_engines 的 engine_stats 字段），'
                         '如 \'[{"engine":"semgrep","rules_run":412,"candidates":520}]\'')
    ap.add_argument("--models", default=None, help="本次所用模型 CSV（如 claude-haiku-4-5,claude-sonnet-4-6）；写入报告头")
    args = ap.parse_args()

    data = load_json(args.findings, default={"findings": []})
    findings = data.get("findings", [])

    engines_used: list[str] = []
    if args.engines_used:
        engines_used = [e.strip() for e in args.engines_used.split(",") if e.strip()]
    engine_stats: list[dict] = []
    if args.engine_stats:
        try:
            parsed = json.loads(args.engine_stats)
            if isinstance(parsed, list):
                engine_stats = parsed
        except (json.JSONDecodeError, TypeError):
            engine_stats = []
    models: list[str] = []
    if args.models:
        models = [m.strip() for m in args.models.split(",") if m.strip()]

    md = _render(findings, engines_used=engines_used, models=models, engine_stats=engine_stats)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    return 0


def _render(findings: list[dict], engines_used: list[str] | None = None, models: list[str] | None = None, engine_stats: list[dict] | None = None) -> str:
    open_items = [f for f in findings if f.get("status") == "open"]

    counts = {sev: 0 for sev, _ in SEVERITY_LABELS}
    for f in open_items:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1

    lines: list[str] = []
    lines.append("# 扫描结果")
    lines.append("")
    # 引擎层级 banner（报告头记录本次实际用的引擎 + 每引擎命中规则数）
    if engine_stats:
        lines.extend(_engine_stats_banner(engine_stats))
        lines.append("")
    elif engines_used:
        lines.append(_engine_banner(engines_used))
        lines.append("")
    if models:
        lines.append(f"> **模型:** {' · '.join(models)}")
        lines.append("")

    total_open = len(open_items)
    lines.append(
        f"**本次发现：** {counts['critical']} critical · {counts['major']} major · "
        f"{counts['minor']} minor · {counts['info']} info（合计 {total_open}）"
    )
    lines.append("")

    for sev_key, sev_label in SEVERITY_LABELS:
        bucket = [f for f in open_items if f.get("severity") == sev_key]
        if not bucket:
            continue
        bucket.sort(key=_sort_key)
        lines.append(f"## {sev_label}")
        lines.append("")
        for f in bucket:
            lines.append(_render_item(f))
            lines.append("---")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _sort_key(f: dict) -> tuple:
    return (
        severity_rank(f.get("severity", "info")),
        f.get("category", ""),
        f.get("file", ""),
        int(f.get("line", 0)),
    )


def _sort_key_resolved(f: dict) -> tuple:
    # 已解决区分 severity，但内部 category/file/line 排序
    return _sort_key(f)


def _engine_banner(engines_used: list[str]) -> str:
    engine_str = " · ".join(f"**{e}** ✓" for e in engines_used)
    return f"> **引擎层级:** {engine_str}"


def _engine_stats_banner(stats: list[dict]) -> list[str]:
    """报告头：本次用了哪些工具引擎 + 每个引擎命中多少条规则 / 产出多少候选。"""
    lines = ["> **本次工具引擎与规则命中：**", ">"]
    for s in stats:
        eng = s.get("engine", "?")
        rr = s.get("rules_run", 0)
        cand = s.get("candidates", 0)
        lines.append(f"> - **{eng}** ✓ — 命中 {rr} 条规则，产出 {cand} 个候选")
    return lines


def _render_item(f: dict) -> str:
    parts: list[str] = []
    parts.append(f"### {f['rule_id']} · {f.get('category', '')}")
    parts.append(f"**{f.get('title', '')}** — {f['file']}:{f['line']}")
    parts.append("")
    if f.get("why"):
        parts.append(f"Why: {f['why']}")
        parts.append("")
    if f.get("evidence"):
        # 依据 file 扩展名选 fence 语言
        lang = _lang_for(f["file"])
        parts.append(f"```{lang}")
        parts.append(f["evidence"])
        parts.append("```")
        parts.append("")
    if f.get("repro"):
        parts.append(f"Repro: {f['repro']}")
    if f.get("suggestion"):
        parts.append(f"Suggestion: {f['suggestion']}")
    # 渲染数据流路径（FlowDroid 产出；Semgrep taint 亦可能带路径）
    dataflow = f.get("dataflow_path", [])
    if dataflow:
        parts.append("")
        parts.append("**数据流路径:**")
        for i, step in enumerate(dataflow):
            step_file = step.get("file", "")
            step_line = step.get("line", 0)
            step_msg = step.get("message", "")
            arrow = "→" if i < len(dataflow) - 1 else "⬇"
            parts.append(f"  {arrow} `{step_file}:{step_line}` — {step_msg}")
    # PoC 结果
    poc = f.get("poc_result", {})
    if poc and poc.get("status") not in (None, "skip"):
        poc_status = poc.get("status", "")
        poc_icon = "🔴" if poc_status == "confirmed" else "🟡"
        parts.append(f"\n{poc_icon} **动态 PoC:** {poc.get('summary', '')}  \n命令: `{poc.get('command', '')}`")
    parts.append("")
    return "\n".join(parts)


def _render_item_compact(f: dict) -> str:
    lines = [
        f"#### {f['rule_id']} · {f.get('category', '')}",
        f"**{f.get('title', '')}** — {f['file']}:{f['line']}",
    ]
    if f.get("suggestion"):
        lines.append(f"Suggestion: {f['suggestion']}")
    lines.append("")
    return "\n".join(lines)


def _lang_for(file_: str) -> str:
    f = file_.lower()
    if f.endswith(".kt"):
        return "kotlin"
    if f.endswith(".xml"):
        return "xml"
    if f.endswith(".java"):
        return "java"
    if f.endswith(".gradle") or f.endswith(".gradle.kts"):
        return "gradle"
    return ""


if __name__ == "__main__":
    sys.exit(main())
