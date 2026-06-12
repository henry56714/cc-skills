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
      "dataflow_path": [...], "poc_result": {...}   (均可选)
    }

输出:
    stdout 一行 JSON 统计：{"findings_total": N, "findings_duplicate": N}
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
PASSTHROUGH_OPTIONAL = ("dataflow_path", "poc_result")


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

    for cand in new_candidates:
        missing = REQUIRED_INPUT_FIELDS - cand.keys()
        if missing:
            print(f"候选缺失字段 {missing}: {cand}", file=sys.stderr)
            return 2

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

    print(json.dumps({
        "findings_total": len(findings_list),
        "findings_duplicate": duplicates,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
