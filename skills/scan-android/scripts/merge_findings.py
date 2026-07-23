#!/usr/bin/env python3
"""
将本次确认的 finding 写入 .scan/findings.json（v3：无状态，每次覆盖）。

v3 决定：去掉跨扫描状态机。本脚本**不**读取旧 findings、不维护 first/last_seen、
不做回归重开 / 关闭消失项——每次扫描独立，只输出本次确认的问题。
跨源/批次去重仅在本次输入内按 finding_id 进行。

用法:
    merge_findings.py [--findings PATH]

从 stdin 读入 JSON 数组，每个元素为本次确认 finding：
    {
      "file": "...", "line": 42, "end_line": 45,  (end_line 可选)
      "rule_id": "R-STB-007", "category": "stability/unnamed-thread",
      "severity": "minor", "title": "...", "evidence": "...",
      "why": "...", "repro": "...", "suggestion": "...",
      "dataflow_path": [...], "poc_result": {...}, "origin_trace": [...]  (均可选)
    }

取证闸（C）：条件触发型类别（static-context-leak / 主线程阻塞 / 越权数据流 等，见
_needs_origin）的 finding 必须带回溯源头链（非空 `dataflow_path` 或 `origin_trace`），
否则视为未取证被丢弃，不进入报告（计入 findings_dropped_no_origin）。

输出:
    stdout 一行 JSON 统计：
    {"findings_total": N, "findings_duplicate": N, "findings_dropped_no_origin": N,
     "dropped_no_origin": [...]}  (后者仅在有丢弃时出现)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib_scan import atomic_write_json, finding_id

REQUIRED_INPUT_FIELDS = {
    "file", "line", "rule_id", "category", "severity",
    "title", "evidence", "why", "repro", "suggestion",
}

# 可选、若存在则原样透传到 finding 记录
PASSTHROUGH_OPTIONAL = ("dataflow_path", "poc_result", "origin_trace")

# 取证闸（C）：以下「条件触发型」类别的缺陷只有在关键值（Context/输入/调用线程）
# 回溯到终端源头后才成立。verifier 须用 nav_tools `trace-origin`（tree-sitter 精确层）取证并把源头链写入
# `dataflow_path`（或显式 `origin_trace`）。缺失源头链的此类 finding 视为**取证未完成**，
# 在此被丢弃，不进入报告——防止「仅凭 sink 模式」的未取证结论混入（见 agents/verifier.md）。
ORIGIN_REQUIRED_PREFIXES = (
    "stability/static-context-leak",
    "perf/main-thread",
    "performance/thread-starvation",
    "performance/main-thread",
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
    # --commit 仅为兼容旧调用而保留，已忽略（v3 去 ledger 后报告不含 commit/时间）
    ap.add_argument("--commit", default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()

    raw = sys.stdin.read().strip()
    new_candidates = json.loads(raw) if raw else []
    if not isinstance(new_candidates, list):
        print("stdin 必须是 JSON 数组", file=sys.stderr)
        return 2

    records: dict[str, dict] = {}
    duplicates = 0
    dropped_no_origin: list[dict] = []

    for cand in new_candidates:
        missing = REQUIRED_INPUT_FIELDS - cand.keys()
        if missing:
            print(f"候选缺失字段 {missing}: {cand}", file=sys.stderr)
            return 2

        # 取证闸（C）：条件触发型缺陷缺少回溯源头链 → 视为未取证，丢弃。
        if _needs_origin(cand.get("category", "")) and not _has_origin(cand):
            dropped_no_origin.append({
                "file": cand.get("file"), "line": cand.get("line"),
                "rule_id": cand.get("rule_id"), "category": cand.get("category"),
            })
            print(
                f"[merge] 丢弃未取证的条件触发型 finding（缺 trace-origin 源头链）: "
                f"{cand.get('rule_id')} @ {cand.get('file')}:{cand.get('line')}",
                file=sys.stderr,
            )
            continue

        fid = finding_id(cand["file"], int(cand["line"]), cand["category"])
        if fid in records:
            duplicates += 1
            continue  # 本次内去重：首个命中保留

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
        }
        for key in PASSTHROUGH_OPTIONAL:
            if cand.get(key):
                record[key] = cand[key]
        records[fid] = record

    findings_list = list(records.values())
    atomic_write_json(args.findings, {"schema_version": 2, "findings": findings_list})

    out = {
        "findings_total": len(findings_list),
        "findings_duplicate": duplicates,
        "findings_dropped_no_origin": len(dropped_no_origin),
    }
    if dropped_no_origin:
        out["dropped_no_origin"] = dropped_no_origin
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
