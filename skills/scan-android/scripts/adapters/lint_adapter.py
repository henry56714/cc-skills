"""Android Lint adapter —— P1 Android 感知扫描。

解析已有 lint-results XML；仅在显式授权后通过 Gradle 生成新报告。
Android Lint 对 manifest / 资源 / API 使用有最精准的感知能力。
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate, resolve_repo_path

from .base import AdapterResult, EngineAdapter, ScanContext

# Lint issue ID → (rule_id, category, severity)
_LINT_RULE_MAP: dict[str, tuple[str, str, str]] = {
    # Security
    "HardcodedCredentials": ("R-LT-001", "security/hardcoded-secret", "critical"),
    "PlaintextPassword": ("R-LT-001", "security/hardcoded-secret", "critical"),
    "VisibleForTests": ("R-LT-001", "security/hardcoded-secret", "info"),
    "OpenForTesting": ("R-LT-001", "security/hardcoded-secret", "info"),
    "TrustAllX509TrustManager": ("R-LT-002", "security/tls-trust-all", "critical"),
    "BadHostnameVerifier": ("R-LT-002", "security/tls-trust-all", "critical"),
    "SetJavaScriptEnabled": ("R-LT-003", "security/webview", "major"),
    "AddJavascriptInterface": ("R-LT-003", "security/webview", "major"),
    "InsecureBaseConfiguration": ("R-LT-004", "security/cleartext", "major"),
    "CleartextSupported": ("R-LT-004", "security/cleartext", "major"),
    "ExportedReceiver": ("R-LT-005", "security/exported-unprotected", "critical"),
    "ExportedActivity": ("R-LT-005", "security/exported-unprotected", "critical"),
    "ExportedService": ("R-LT-005", "security/exported-unprotected", "critical"),
    "WorldReadableFiles": ("R-LT-006", "security/world-readable", "critical"),
    "WorldWriteableFiles": ("R-LT-006", "security/world-readable", "critical"),
    "SQLiteString": ("R-LT-007", "security/sql-injection", "critical"),
    "HardcodedDebugMode": ("R-LT-008", "security/debuggable-enabled", "critical"),
    "AllowBackup": ("R-LT-009", "security/backup-allowed", "major"),
    "UnsafeIntentLaunch": ("R-LT-010", "security/intent-redirection", "critical"),
    "IntentFilterUniquePermission": ("R-LT-011", "security/receiver-export-flag", "major"),
    "ExportedProvider": ("R-LT-012", "security/exported-provider", "critical"),
    # Stability
    "Recycle": ("R-LT-013", "stability/resource-leak-cursor", "major"),
    "Registered": ("R-LT-014", "stability/listener-leak", "major"),
    "ObsoleteSdkInt": ("R-LT-015", "stability/deprecated-asynctask", "info"),
    "DiscouragedApi": ("R-LT-015", "stability/deprecated-asynctask", "minor"),
    "CommitTransaction": ("R-LT-016", "stability/fragment-state-loss", "major"),
    "StaticFieldLeak": ("R-LT-017", "stability/static-context-leak", "critical"),
    "CoarseFineLocation": ("R-LT-022", "stability/location-permission-pair", "critical"),
    "SoonBlockedPrivateApi": ("R-LT-023", "stability/non-sdk-api-enforcement", "critical"),
    "PrivateApi": ("R-LT-023", "stability/non-sdk-api-enforcement", "major"),
    # Performance
    "WrongThread": ("R-LT-018", "perf/main-thread-io", "major"),
    "ViewHolder": ("R-LT-019", "perf/rv-findviewbyid", "major"),
    "UseBindingAdapter": ("R-LT-019", "perf/rv-findviewbyid", "info"),
    "DrawAllocation": ("R-LT-020", "perf/hotpath-allocation", "major"),
    "InefficientWeight": ("R-LT-020", "perf/hotpath-allocation", "minor"),
    "NestedWeights": ("R-LT-020", "perf/hotpath-allocation", "minor"),
    "DisableBaselineAlignment": ("R-LT-020", "perf/hotpath-allocation", "info"),
    "UnusedResources": ("R-LT-021", "perf/unbounded-cache", "info"),
}

_LINT_SEV_MAP = {
    "Fatal": "critical",
    "Error": "critical",
    "Warning": "major",
    "Information": "info",
    "Ignore": "info",
}


class LintAdapter(EngineAdapter):
    name = "lint"

    def is_available(self, ctx: ScanContext) -> tuple[bool, str]:
        if not ctx.allow_build_execution:
            reports = _existing_reports(ctx)
            if reports:
                return True, ""
            return False, (
                "未发现已有 lint-results XML，且未获授权执行 Gradle/Lint；确认仓库可信后传 "
                "--allow-build-execution"
            )
        gradlew = ctx.repo / "gradlew"
        try:
            gradlew = resolve_repo_path(ctx.repo, gradlew, label="Gradle wrapper")
        except ValueError as exc:
            return False, str(exc)
        if not gradlew.is_file():
            return False, f"gradlew 未找到（{gradlew}），Android Lint 不可用"
        return True, ""

    def run(self, ctx: ScanContext) -> AdapterResult:
        result = AdapterResult(engine=self.name)
        if not ctx.allow_build_execution:
            reports = _existing_reports(ctx)
            if not reports:
                result.available = False
                result.status = "failed"
                result.unavailable_reason = "没有可只读解析的 Lint XML"
                return result
            _populate_from_reports(result, reports, ctx)
            # Existing reports may represent a different variant or stale source.
            # Retain their high-value findings but never claim complete coverage.
            result.status = "partial"
            result.notes.append({
                "engine": self.name,
                "note": "只读解析已有 Lint XML；未执行 Gradle，无法证明报告对应当前源码和目标变体",
                "reports": [str(path.relative_to(ctx.repo.resolve())) for path in reports],
            })
            return result

        gradlew = ctx.repo / "gradlew"
        try:
            gradlew = resolve_repo_path(ctx.repo, gradlew, label="Gradle wrapper")
        except ValueError as exc:
            result.available = False
            result.status = "failed"
            result.unavailable_reason = str(exc)
            return result
        if not gradlew.is_file():
            result.available = False
            result.unavailable_reason = "gradlew 未找到"
            return result

        lint_tasks = ctx.detect_info.get("suggested_lint_tasks", ["lintRelease", "lint"])
        if not isinstance(lint_tasks, list):
            lint_tasks = []
        unsafe_tasks = [
            str(task) for task in lint_tasks
            if not isinstance(task, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9:_-]*", task)
        ]
        lint_tasks = [
            task for task in lint_tasks
            if isinstance(task, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9:_-]*", task)
        ]
        if unsafe_tasks:
            result.status = "partial"
            result.notes.append({
                "engine": self.name,
                "note": "拒绝不安全的 Gradle task 名称",
                "tasks": unsafe_tasks,
            })
        ran_tasks: list[str] = []
        tasks_with_reports: list[str] = []
        tasks_without_reports: list[str] = []
        xml_reports: list[Path] = []
        task_succeeded_without_report = False

        for task in lint_tasks:
            launcher = [str(gradlew)] if os.access(gradlew, os.X_OK) else ["bash", str(gradlew)]
            cmd = launcher + [task, "--no-daemon", "--continue"]
            before = {
                p: p.stat().st_mtime_ns for p in _discovered_reports(ctx.repo)
            }
            try:
                ran_tasks.append(task)
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    cwd=str(ctx.repo),
                )
                reports = _discovered_reports(ctx.repo)
                fresh = [
                    p for p in reports
                    if p not in before or p.stat().st_mtime_ns > before[p]
                ]
                # Lint 发现问题时可能非零退出，但会写出报告；无新报告的失败 task 继续尝试。
                if fresh:
                    tasks_with_reports.append(task)
                    xml_reports.extend(fresh)
                    continue
                if proc.returncode == 0:
                    task_succeeded_without_report = True
                    tasks_without_reports.append(task)
                    result.notes.append({
                        "engine": self.name,
                        "note": f"lint 任务 {task} 成功但未产生新的 XML 报告，继续尝试",
                    })
                    continue
                result.notes.append({
                    "engine": self.name,
                    "note": f"lint 任务 {task} 失败且未产生报告: {(proc.stderr or proc.stdout)[-300:]}",
                })
                tasks_without_reports.append(task)
            except subprocess.TimeoutExpired:
                result.status = "partial"
                tasks_without_reports.append(task)
                result.notes.append({"engine": self.name, "note": f"lint 任务 {task} 超时（600s）"})
                continue
            except Exception as e:
                result.status = "partial"
                tasks_without_reports.append(task)
                result.notes.append({"engine": self.name, "note": f"lint 任务 {task} 失败: {e}"})
                continue

        if not tasks_with_reports:
            result.available = False
            result.status = "failed"
            result.unavailable_reason = (
                "Lint 任务完成但未产生新的 XML 报告"
                if task_succeeded_without_report else "所有 lint Gradle 任务均失败"
            )
            return result

        _populate_from_reports(result, sorted(set(xml_reports)), ctx)
        if tasks_without_reports or unsafe_tasks:
            result.status = "partial"
        result.notes.append({
            "engine": self.name,
            "note": "已执行并逐项记账 shipping lint 任务",
            "tasks_ran": ran_tasks,
            "tasks_with_fresh_reports": tasks_with_reports,
            "tasks_without_fresh_reports": tasks_without_reports,
        })
        return result


def _existing_reports(ctx: ScanContext) -> list[Path]:
    """Return explicit or discovered reports without executing project code."""
    config = ctx.detect_info.get("config", {}) if isinstance(ctx.detect_info, dict) else {}
    configured = config.get("lint_report_paths", []) if isinstance(config, dict) else []
    reports: list[Path] = []
    if isinstance(configured, list):
        for raw in configured:
            if not isinstance(raw, str):
                continue
            path = Path(raw)
            path = path if path.is_absolute() else ctx.repo / path
            try:
                path = resolve_repo_path(ctx.repo, path, label="Lint report")
            except ValueError:
                continue
            if path.is_file() and path.suffix.lower() == ".xml":
                reports.append(path)
    if not reports:
        reports = _discovered_reports(ctx.repo)
    return sorted(dict.fromkeys(path.resolve() for path in reports))


def _discovered_reports(repo: Path) -> list[Path]:
    """Discover reports without following target-controlled links outside repo."""
    reports: list[Path] = []
    for candidate in repo.rglob("lint-results*.xml"):
        try:
            resolved = resolve_repo_path(repo, candidate, label="Lint report")
        except ValueError:
            continue
        if resolved.is_file() and resolved.suffix.lower() == ".xml":
            reports.append(resolved)
    return sorted(dict.fromkeys(reports))


def _populate_from_reports(result: AdapterResult, reports: list[Path], ctx: ScanContext) -> None:
    scope_set = set(ctx.scope_files)
    rules_seen: set[str] = set()
    for report_path in reports:
        try:
            candidates, issues = _parse_lint_xml(report_path, ctx.repo, scope_set)
            result.candidates.extend(candidates)
            rules_seen.update(issues)
        except Exception as exc:
            result.status = "partial"
            result.notes.append({
                "engine": "lint",
                "note": f"lint 报告 {report_path.name} 解析失败: {exc}",
            })
    result.rules_run = len(rules_seen)
    # Lint XML contains triggered issue ids only, not the configured registry.
    result.rules_total = 0


def _parse_lint_xml(
    report_path: Path,
    repo: Path,
    scope_set: set[str],
) -> tuple[list[Candidate], set[str]]:
    repo = repo.resolve()
    tree = ET.parse(report_path)
    root = tree.getroot()
    candidates: list[Candidate] = []
    issues_seen: set[str] = set()

    for issue in root.findall("issue"):
        issue_id = issue.get("id", "")
        issues_seen.add(issue_id)

        rule_id, category, severity = _LINT_RULE_MAP.get(
            issue_id,
            (f"R-LT-{issue_id}", f"lint/{issue_id.lower()}", _LINT_SEV_MAP.get(issue.get("severity", "Warning"), "minor")),
        )
        if issue_id not in _LINT_RULE_MAP:
            # 未映射的 Warning 也必须进入候选池；映射缺失不能变成静默漏报。
            lint_sev = issue.get("severity", "Warning")
            if lint_sev == "Ignore":
                continue
            severity = _LINT_SEV_MAP.get(lint_sev, "minor")

        message = issue.get("message", "")

        for location in issue.findall("location"):
            file_str = location.get("file", "")
            rel = _normalize_lint_location(file_str, repo, scope_set)
            if scope_set and rel not in scope_set:
                continue

            line = int(location.get("line", 0))
            candidates.append(Candidate(
                engine="lint",
                rule_id=rule_id,
                native_rule_id=issue_id,
                file=rel,
                line=line,
                category=category,
                severity=severity,
                message=message,
            ))

    return candidates, issues_seen


def _normalize_lint_location(file_str: str, repo: Path, scope_set: set[str]) -> str:
    """Normalize absolute report paths, including reports copied with a repo."""
    normalized = file_str.replace("\\", "/")
    try:
        return Path(file_str).resolve().relative_to(repo).as_posix()
    except ValueError:
        pass
    suffix_matches = [rel for rel in scope_set if normalized.endswith("/" + rel) or normalized == rel]
    return min(suffix_matches, key=len) if suffix_matches else normalized
