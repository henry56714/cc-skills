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
        gradlew = ctx.repo / "gradlew"
        if not gradlew.exists():
            return False, f"gradlew 未找到（{gradlew}），Android Lint 不可用"
        if not os.access(gradlew, os.X_OK):
            gradlew.chmod(gradlew.stat().st_mode | 0o111)
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

        for task in lint_tasks:
            cmd = [str(gradlew), task, "--no-daemon", "--continue"]
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    cwd=str(ctx.repo),
                )
                # Gradle 失败码非 0 但可能仍写出了报告
                ran_task = task
                break
            except subprocess.TimeoutExpired:
                result.notes.append({"engine": self.name, "note": f"lint 任务 {task} 超时（600s）"})
                continue
            except Exception as e:
                result.notes.append({"engine": self.name, "note": f"lint 任务 {task} 失败: {e}"})
                continue

        if ran_task is None:
            result.available = False
            result.unavailable_reason = "所有 lint Gradle 任务均失败"
            return result

        # 寻找 lint 报告文件
        xml_reports = list(ctx.repo.rglob("lint-results*.xml"))
        if not xml_reports:
            # 有些版本的 lint 输出到不同路径
            xml_reports = list(ctx.repo.glob("**/reports/lint/lint-results*.xml"))
        if not xml_reports:
            result.notes.append({"engine": self.name, "note": "未找到 lint XML 报告"})
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
            # 未映射的 lint issue：只在 critical/error 级别记录
            lint_sev = issue.get("severity", "Warning")
            if lint_sev not in ("Fatal", "Error"):
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
