#!/usr/bin/env python3
"""
从 findings / needs-review JSON 渲染两个独立报告。

用法:
    render_report.py [--findings PATH] [--needs-review PATH] [--output PATH]

排序：severity (critical→major→minor→info) → category asc → file asc → line asc。

v4：无状态、无 ledger——报告不含 commit/时间，仅展示本次扫描确认的问题；
同时展示本次运行 ID、结构化根因的关联位置与候选溯源摘要。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib_scan import (
    atomic_write_json,
    load_json,
    now_iso,
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
    ap.add_argument("--needs-review", default=".scan/needs-review.json")
    ap.add_argument("--output", default=".scan/reports/findings.md")
    ap.add_argument("--needs-review-output", default=".scan/reports/needs-review.md")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument(
        "--engine-results", default=".scan/tmp/engine-results.json",
        help="run_engines.py 的完整 JSON 输出文件；优先于 --engine-stats",
    )
    ap.add_argument("--engines-used", default=None, help="已使用引擎 CSV（如 semgrep,detekt）；写入报告头")
    ap.add_argument("--engine-stats", default=None,
                    help='每引擎规则/候选数的 JSON（run_engines 的 engine_stats 字段），'
                         '如 \'[{"engine":"semgrep","rules_run":412,"candidates":520}]\'')
    ap.add_argument("--models", default=None, help="本次所用模型 CSV（如 claude-haiku-4-5,claude-sonnet-4-6）；写入报告头")
    ap.add_argument("--language", choices=("auto", "zh", "en"), default="auto")
    ap.add_argument("--run-manifest", default=".scan/tmp/run_manifest.json")
    ap.add_argument("--hunt-coverage-result", default=".scan/tmp/hunt_perspective_coverage.json")
    ap.add_argument("--verify-coverage", default=".scan/tmp/verify_coverage.json")
    ap.add_argument("--merge-receipt", default=".scan/tmp/merge_receipt.json")
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()

    findings_path = _repo_path(repo, args.findings)
    needs_review_path = _repo_path(repo, args.needs_review)
    run_manifest_path = _repo_path(repo, args.run_manifest)
    data = load_json(str(findings_path), default={"findings": []})
    findings = data.get("findings", [])
    review_data = load_json(str(needs_review_path), default={"needs_review": []})
    needs_review = review_data.get("needs_review", [])
    run_manifest = load_json(str(run_manifest_path), default={})
    language = args.language
    if language == "auto":
        language = run_manifest.get("language", "zh") if isinstance(run_manifest, dict) else "zh"
    if language not in ("zh", "en"):
        language = "zh"

    engines_used: list[str] = []
    if args.engines_used:
        engines_used = [e.strip() for e in args.engines_used.split(",") if e.strip()]
    engine_stats, engine_gate = _load_engine_stats(
        _repo_path(repo, args.engine_results), args.engine_stats,
    )
    pipeline_stats = [engine_gate] + _pipeline_stats(
        repo=repo,
        hunt_result=_repo_path(repo, args.hunt_coverage_result),
        verify_coverage=_repo_path(repo, args.verify_coverage),
        merge_receipt=_repo_path(repo, args.merge_receipt),
        findings_path=findings_path,
        needs_review_path=needs_review_path,
        findings_count=len(findings),
        needs_review_count=len(needs_review),
        run_manifest=run_manifest if isinstance(run_manifest, dict) else {},
    )
    all_stats = engine_stats + pipeline_stats
    models: list[str] = []
    if args.models:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
    if not models:
        models = ["unknown"]

    md = _render(
        findings, engines_used=engines_used, models=models,
        engine_stats=all_stats, language=language, run_manifest=run_manifest,
    )
    out = _repo_path(repo, args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    review_out = _repo_path(repo, args.needs_review_output)
    review_out.parent.mkdir(parents=True, exist_ok=True)
    review_out.write_text(_render_needs_review(needs_review, language=language), encoding="utf-8")
    if isinstance(run_manifest, dict) and run_manifest:
        finalized = dict(run_manifest)
        finalized.update({
            "finished_at": now_iso(),
            "models": models,
            "engine_stats": engine_stats,
            "pipeline_stats": pipeline_stats,
            "coverage_status": _coverage_status(all_stats),
            "coverage_gaps": [
                {"phase": s.get("engine"), "reason": s.get("reason", s.get("status"))}
                for s in all_stats if s.get("status") in {"partial", "failed", "skipped"}
            ],
            "results": {"confirmed": len(findings), "needs_review": len(needs_review)},
        })
        atomic_write_json(run_manifest_path, finalized)
    return 0


def _repo_path(repo: Path, raw: str) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else repo / path


def _read_object(path: Path) -> tuple[dict | None, str]:
    if not path.is_file():
        return None, f"missing artifact: {path}"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"invalid JSON {path}: {exc}"
    if not isinstance(value, dict):
        return None, f"artifact must be a JSON object: {path}"
    return value, ""


def _phase(name: str, status: str, reason: str = "") -> dict:
    item = {
        "engine": name,
        "kind": "pipeline",
        "status": status,
        "rules_run": 0,
        "rules_triggered": 0,
        "candidates": 0,
        "truncated": 0,
    }
    if reason:
        item["reason"] = reason
    return item


def _load_engine_stats(path: Path, raw_fallback: str | None) -> tuple[list[dict], dict]:
    obj, error = _read_object(path)
    if obj is not None and isinstance(obj.get("engine_stats"), list):
        stats = [item for item in obj["engine_stats"] if isinstance(item, dict)]
        if not stats or len(stats) != len(obj["engine_stats"]) or not isinstance(obj.get("candidates"), list):
            return stats, _phase(
                "engine_results", "failed",
                "engine_results must contain non-empty object stats and a candidates array",
            )
        expected_status = str(obj.get("status", "incomplete"))
        actual_status = _coverage_status(stats)
        if expected_status != actual_status:
            return stats, _phase(
                "engine_results", "failed",
                f"engine result status mismatch: declared={expected_status}, derived={actual_status}",
            )
        return stats, _phase("engine_results", "complete")

    if raw_fallback:
        try:
            parsed = json.loads(raw_fallback)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, list) and all(isinstance(item, dict) for item in parsed):
            return parsed, _phase(
                "engine_results", "failed",
                "used legacy --engine-stats; complete engine-results artifact is required",
            )
    return [], _phase("engine_results", "failed", error or "engine_results lacks engine_stats")


def _pipeline_stats(
    *, repo: Path, hunt_result: Path, verify_coverage: Path, merge_receipt: Path,
    findings_path: Path, needs_review_path: Path, findings_count: int,
    needs_review_count: int, run_manifest: dict,
) -> list[dict]:
    stats: list[dict] = []
    config, _ = _read_object(repo / ".scan" / "config.json")
    excluded = (
        set(config.get("excluded_engines", []))
        if isinstance(config, dict)
        and isinstance(config.get("excluded_engines", []), list)
        else set()
    )
    hunt_scope = repo / ".scan" / "tmp" / "hunt_scope.txt"
    if "ai" in excluded:
        stats.append(_phase("ai_hunter", "skipped", "excluded_engines configuration"))
    elif not hunt_scope.is_file():
        stats.append(_phase("ai_hunter", "failed", f"missing artifact: {hunt_scope}"))
    elif not hunt_scope.read_text(encoding="utf-8").strip():
        stats.append(_phase("ai_hunter", "not_applicable"))
    else:
        hunt, error = _read_object(hunt_result)
        stats.append(_phase(
            "ai_hunter",
            "complete" if hunt is not None and hunt.get("ok") is True else "failed",
            "" if hunt is not None and hunt.get("ok") is True else error or "hunter coverage ok=false",
        ))

    verify, error = _read_object(verify_coverage)
    verify_ok = (
        verify is not None
        and verify.get("coverage_ok") is True
        and type(verify.get("candidates_input")) is int
        and verify.get("candidates_input") == verify.get("candidates_batched")
        and isinstance(verify.get("batch_files"), list)
        and verify.get("batches") == len(verify.get("batch_files"))
    )
    stats.append(_phase(
        "verifier", "complete" if verify_ok else "failed",
        "" if verify_ok else error or "verify coverage is invalid or not lossless",
    ))

    receipt, error = _read_object(merge_receipt)
    run_id = run_manifest.get("run_id")
    artifacts_ok, artifacts_error = _verify_receipt_artifacts(repo, receipt)
    receipt_ok = (
        receipt is not None
        and receipt.get("ok") is True
        and findings_path.is_file()
        and needs_review_path.is_file()
        and receipt.get("results") == {
            "confirmed": findings_count, "needs_review": needs_review_count,
        }
        and (not run_id or receipt.get("run_id") == run_id)
        and artifacts_ok
    )
    stats.append(_phase(
        "merge", "complete" if receipt_ok else "failed",
        "" if receipt_ok else (
            error or artifacts_error
            or (str(receipt.get("reason", "")) if isinstance(receipt, dict) else "")
            or "merge receipt/results/run_id mismatch"
        ),
    ))
    return stats


def _verify_receipt_artifacts(repo: Path, receipt: dict | None) -> tuple[bool, str]:
    if not isinstance(receipt, dict):
        return False, "merge receipt is missing"
    artifacts = receipt.get("artifacts_sha256")
    if not isinstance(artifacts, list) or not artifacts:
        return False, "merge receipt lacks artifact digests"
    for item in artifacts:
        if not isinstance(item, dict):
            return False, "merge receipt contains an invalid artifact digest"
        raw_path = item.get("path")
        expected = item.get("sha256")
        if not isinstance(raw_path, str) or not isinstance(expected, str):
            return False, "merge receipt contains an invalid artifact digest"
        path = _repo_path(repo, raw_path)
        if not path.is_file():
            return False, f"merge artifact is missing: {path}"
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            return False, f"merge artifact changed after verification: {path}"
    return True, ""


def _render(
    findings: list[dict], engines_used: list[str] | None = None,
    models: list[str] | None = None, engine_stats: list[dict] | None = None,
    language: str = "zh", run_manifest: dict | None = None,
) -> str:
    open_items = [f for f in findings if f.get("status") == "open"]

    counts = {sev: 0 for sev, _ in SEVERITY_LABELS}
    for f in open_items:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1

    lines: list[str] = []
    lines.append("# 扫描结果" if language == "zh" else "# Scan results")
    lines.append("")
    if run_manifest and run_manifest.get("run_id"):
        label = "运行 ID" if language == "zh" else "Run ID"
        lines.append(f"> **{label}:** `{run_manifest['run_id']}`")
        lines.append("")
    # 引擎层级 banner（报告头记录本次实际用的引擎 + 每引擎命中规则数）
    if engine_stats:
        lines.extend(_engine_stats_banner(engine_stats, language=language))
        lines.append("")
    elif engines_used:
        lines.append(_engine_banner(engines_used))
        lines.append("")
    if models:
        label = "模型" if language == "zh" else "Models"
        lines.append(f"> **{label}:** {' · '.join(models)}")
        lines.append("")

    total_open = len(open_items)
    if language == "zh":
        lines.append(
            f"**本次发现：** {counts['critical']} critical · {counts['major']} major · "
            f"{counts['minor']} minor · {counts['info']} info（合计 {total_open}）"
        )
    else:
        lines.append(
            f"**Findings:** {counts['critical']} critical · {counts['major']} major · "
            f"{counts['minor']} minor · {counts['info']} info ({total_open} total)"
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
            lines.append(_render_item(f, language=language))
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


def _engine_stats_banner(stats: list[dict], language: str = "zh") -> list[str]:
    """报告头：本次用了哪些工具引擎 + 每个引擎命中多少条规则 / 产出多少候选。"""
    incomplete = [s for s in stats if s.get("status", "complete") in ("partial", "failed")]
    skipped = [s for s in stats if s.get("status") == "skipped"]
    lines = []
    if incomplete:
        message = (
            "> ⚠️ **扫描不完整：** 部分引擎未完成；下方结果仍有效，但不能解释为“未发现其他问题”。"
            if language == "zh" else
            "> ⚠️ **Incomplete scan:** some engines did not finish; retained results remain valid but are not a clean bill of health."
        )
        lines.extend([message, ">"])
    elif skipped:
        message = (
            "> ⚠️ **覆盖受限：** 部分能力被显式排除或因安全授权缺失而跳过。"
            if language == "zh" else
            "> ⚠️ **Limited coverage:** some capabilities were excluded or skipped because authorization was not granted."
        )
        lines.extend([message, ">"])
    heading = "> **扫描引擎与阶段结果：**" if language == "zh" else "> **Engine and pipeline results:**"
    lines.extend([heading, ">"])
    for s in stats:
        eng = s.get("engine", "?")
        rr = s.get("rules_triggered", s.get("rules_run", 0))
        configured = s.get("rules_configured")
        cand = s.get("candidates", 0)
        status = s.get("status", "complete")
        icon = "✓" if status == "complete" else "○" if status == "not_applicable" else "⚠" if status == "partial" else "✗" if status == "failed" else "–"
        detail = (
            f"状态 {status}；触发 {rr} 种规则，{cand} 个候选进入验证"
            if language == "zh" else
            f"status {status}; {rr} rule kinds triggered; {cand} candidates sent to verification"
        )
        if isinstance(configured, int) and configured > 0:
            detail += (
                f"；配置 {configured} 条规则"
                if language == "zh" else f"; {configured} rules configured"
            )
        if s.get("suppressed"):
            detail += (
                f"；显式抑制 {s['suppressed']} 条 advisory/style 命中"
                if language == "zh" else
                f"; {s['suppressed']} advisory/style hits explicitly suppressed"
            )
        if s.get("truncated"):
            detail += f"；截断 {s['truncated']} 个"
        if s.get("reason"):
            detail += f"；{s['reason']}"
        lines.append(f"> - **{eng}** {icon} — {detail}")
    return lines


def _render_needs_review(items: list[dict], language: str = "zh") -> str:
    """Render inconclusive candidates without presenting them as confirmed bugs."""
    rows = sorted(items, key=_sort_key)
    lines = ([
        "# 待复核项", "",
        "> 这些条目有有效线索，但当前证据不足以确认或排除。它们不计入正式 finding。", "",
        f"**待复核：** {len(rows)}", "",
    ] if language == "zh" else [
        "# Needs review", "",
        "> These items have useful signals, but current evidence is insufficient to confirm or reject them. They are not confirmed findings.", "",
        f"**Needs review:** {len(rows)}", "",
    ])
    for item in rows:
        lines.append(f"## {item.get('rule_id', '?')} · {item.get('title', '')}")
        lines.append("")
        label = "位置" if language == "zh" else "Location"
        lines.append(f"{label}: `{item.get('file', '')}:{item.get('line', 0)}`")
        lines.append("")
        label = "复核原因" if language == "zh" else "Review reason"
        default_reason = "证据不足" if language == "zh" else "Insufficient evidence"
        lines.append(f"{label}: {item.get('review_reason', default_reason)}")
        if item.get("missing_evidence"):
            missing = item["missing_evidence"]
            missing_text = "、".join(str(x) for x in missing) if isinstance(missing, list) else str(missing)
            lines.append("")
            label = "缺少证据" if language == "zh" else "Missing evidence"
            lines.append(f"{label}: {missing_text}")
        if item.get("evidence"):
            label = "现有线索：" if language == "zh" else "Current evidence:"
            lines.extend(["", label, "", f"```{_lang_for(item.get('file', ''))}", item["evidence"], "```"])
        lines.extend(["", "---", ""])
    return "\n".join(lines).rstrip() + "\n"


def _render_item(f: dict, language: str = "zh") -> str:
    parts: list[str] = []
    parts.append(f"### {f['rule_id']} · {f.get('category', '')}")
    parts.append(f"**{f.get('title', '')}** — {f['file']}:{f['line']}")
    parts.append("")
    if f.get("why"):
        parts.append(f"{'原因' if language == 'zh' else 'Why'}: {f['why']}")
        parts.append("")
    if f.get("evidence"):
        # 依据 file 扩展名选 fence 语言
        lang = _lang_for(f["file"])
        parts.append(f"```{lang}")
        parts.append(f["evidence"])
        parts.append("```")
        parts.append("")
    if f.get("repro"):
        parts.append(f"{'复现' if language == 'zh' else 'Repro'}: {f['repro']}")
    if f.get("suggestion"):
        parts.append(f"{'修复建议' if language == 'zh' else 'Suggestion'}: {f['suggestion']}")
    # 渲染 Semgrep taint 或 verifier 复核得到的数据流路径
    dataflow = f.get("dataflow_path", [])
    if dataflow:
        parts.append("")
        parts.append("**数据流路径:**" if language == "zh" else "**Dataflow path:**")
        for i, step in enumerate(dataflow):
            step_file = step.get("file", "")
            step_line = step.get("line", 0)
            step_msg = step.get("message", "")
            arrow = "→" if i < len(dataflow) - 1 else "⬇"
            parts.append(f"  {arrow} `{step_file}:{step_line}` — {step_msg}")
    related = f.get("related_locations", [])
    if isinstance(related, list) and len(related) > 1:
        parts.append("")
        parts.append("**相关定位:**" if language == "zh" else "**Related locations:**")
        for location in related:
            parts.append(
                f"- `{location.get('file', '')}:{location.get('line', 0)}` — "
                f"{location.get('title') or location.get('category', '')}"
            )
    source_ids = f.get("source_candidate_ids", [])
    if isinstance(source_ids, list) and source_ids:
        label = "来源候选" if language == "zh" else "Source candidates"
        parts.append(f"\n**{label}:** {len(source_ids)}")
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


def _coverage_status(stats: list[dict]) -> str:
    statuses = {str(s.get("status", "complete")) for s in stats}
    if statuses & {"partial", "failed"}:
        return "incomplete"
    if "skipped" in statuses:
        return "complete_with_skips"
    return "complete"


if __name__ == "__main__":
    sys.exit(main())
