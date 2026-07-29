"""Android Lint adapter —— P1 Android 感知扫描。

通过项目的 Gradle wrapper 运行 lint 任务，解析 lint-results.xml。
Android Lint 对 manifest / 资源 / API 使用有最精准的感知能力。
"""

from __future__ import annotations

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate

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
            return False, (
                "Lint 需要执行仓库 Gradle 构建逻辑；默认禁用。确认仓库可信后传 "
                "--allow-build-execution 或配置 allow_gradle_execution=true"
            )
        gradlew = ctx.repo / "gradlew"
        if not gradlew.exists():
            return False, f"gradlew 未找到（{gradlew}），Android Lint 不可用"
        return True, ""

    def run(self, ctx: ScanContext) -> AdapterResult:
        result = AdapterResult(engine=self.name)
        gradlew = ctx.repo / "gradlew"
        if not gradlew.exists():
            result.available = False
            result.unavailable_reason = "gradlew 未找到"
            return result

        lint_tasks = ctx.detect_info.get("suggested_lint_tasks", ["lintDebug", "lint"])
        ran_task = None
        xml_reports: list[Path] = []
        task_succeeded_without_report = False

        for task in lint_tasks:
            launcher = [str(gradlew)] if os.access(gradlew, os.X_OK) else ["bash", str(gradlew)]
            cmd = launcher + [task, "--no-daemon", "--continue"]
            before = {
                p.resolve(): p.stat().st_mtime_ns
                for p in ctx.repo.rglob("lint-results*.xml")
            }
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    cwd=str(ctx.repo),
                )
                reports = list(ctx.repo.rglob("lint-results*.xml"))
                fresh = [
                    p for p in reports
                    if p.resolve() not in before or p.stat().st_mtime_ns > before[p.resolve()]
                ]
                # Lint 发现问题时可能非零退出，但会写出报告；无新报告的失败 task 继续尝试。
                if fresh:
                    ran_task = task
                    xml_reports = fresh
                    break
                if proc.returncode == 0:
                    task_succeeded_without_report = True
                    result.notes.append({
                        "engine": self.name,
                        "note": f"lint 任务 {task} 成功但未产生新的 XML 报告，继续尝试",
                    })
                    continue
                result.notes.append({
                    "engine": self.name,
                    "note": f"lint 任务 {task} 失败且未产生报告: {(proc.stderr or proc.stdout)[-300:]}",
                })
            except subprocess.TimeoutExpired:
                result.status = "partial"
                result.notes.append({"engine": self.name, "note": f"lint 任务 {task} 超时（600s）"})
                continue
            except Exception as e:
                result.status = "partial"
                result.notes.append({"engine": self.name, "note": f"lint 任务 {task} 失败: {e}"})
                continue

        if ran_task is None:
            result.available = False
            result.status = "failed"
            result.unavailable_reason = (
                "Lint 任务完成但未产生新的 XML 报告"
                if task_succeeded_without_report else "所有 lint Gradle 任务均失败"
            )
            return result

        scope_set = set(ctx.scope_files)
        all_candidates: list[Candidate] = []
        rules_seen: set[str] = set()

        for report_path in xml_reports:
            try:
                candidates, issues = _parse_lint_xml(report_path, ctx.repo, scope_set)
                all_candidates.extend(candidates)
                rules_seen.update(issues)
            except Exception as e:
                result.status = "partial"
                result.notes.append({
                    "engine": self.name,
                    "note": f"lint 报告 {report_path.name} 解析失败: {e}",
                })

        result.candidates = all_candidates
        result.rules_run = len(rules_seen)
        result.rules_total = len(rules_seen)
        result.notes.append({"engine": self.name, "note": f"已运行 lint 任务: {ran_task}"})
        return result


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
            try:
                rel = Path(file_str).resolve().relative_to(repo).as_posix()
            except ValueError:
                rel = file_str
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
