"""Android Lint adapter —— P1 Android 感知扫描。

通过项目的 Gradle wrapper 运行 lint 任务，解析 lint-results.xml。
Android Lint 对 manifest / 资源 / API 使用有最精准的感知能力。
"""

from __future__ import annotations

import os
import shutil
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
    "HardcodedDebugMode": ("R-SEC-014", "security/debuggable-enabled", "critical"),
    "AllowBackup": ("R-SEC-015", "security/backup-allowed", "major"),
    "ExportedReceiver": ("R-SEC-007", "security/exported-unprotected", "critical"),
    "ExportedActivity": ("R-SEC-007", "security/exported-unprotected", "critical"),
    "ExportedService": ("R-SEC-007", "security/exported-unprotected", "critical"),
    "ExportedProvider": ("R-SEC-018", "security/exported-provider", "critical"),
    "SetJavaScriptEnabled": ("R-SEC-004", "security/webview", "major"),
    "AddJavascriptInterface": ("R-SEC-004", "security/webview", "major"),
    "SQLiteString": ("R-SEC-011", "security/sql-injection", "critical"),
    "HardcodedCredentials": ("R-SEC-001", "security/hardcoded-secret", "critical"),
    "PlaintextPassword": ("R-SEC-001", "security/hardcoded-secret", "critical"),
    "TrustAllX509TrustManager": ("R-SEC-003", "security/tls-trust-all", "critical"),
    "BadHostnameVerifier": ("R-SEC-003", "security/tls-trust-all", "critical"),
    "InsecureBaseConfiguration": ("R-SEC-005", "security/cleartext", "major"),
    "CleartextSupported": ("R-SEC-005", "security/cleartext", "major"),
    "WorldReadableFiles": ("R-SEC-008", "security/world-readable", "critical"),
    "WorldWriteableFiles": ("R-SEC-008", "security/world-readable", "critical"),
    "UnsafeIntentLaunch": ("R-SEC-016", "security/intent-redirection", "critical"),
    "IntentFilterUniquePermission": ("R-SEC-017", "security/receiver-export-flag", "major"),
    # Stability
    "Recycle": ("R-STB-001", "stability/resource-leak-cursor", "major"),
    "Registered": ("R-STB-003", "stability/listener-leak", "major"),
    "ViewHolder": ("R-PRF-005", "perf/rv-findviewbyid", "major"),
    "ObsoleteSdkInt": ("R-STB-006", "stability/deprecated-asynctask", "info"),
    "CommitTransaction": ("R-STB-011", "stability/fragment-state-loss", "major"),
    "WrongThread": ("R-PRF-001", "perf/main-thread-io", "major"),
    "DiscouragedApi": ("R-STB-006", "stability/deprecated-asynctask", "minor"),
    "VisibleForTests": ("R-SEC-001", "security/hardcoded-secret", "info"),
    # Performance
    "DrawAllocation": ("R-PRF-004", "perf/hotpath-allocation", "major"),
    "UseBindingAdapter": ("R-PRF-005", "perf/rv-findviewbyid", "info"),
    "UnusedResources": ("R-PRF-011", "perf/unbounded-cache", "info"),
    "InefficientWeight": ("R-PRF-004", "perf/hotpath-allocation", "minor"),
    "NestedWeights": ("R-PRF-004", "perf/hotpath-allocation", "minor"),
    "DisableBaselineAlignment": ("R-PRF-004", "perf/hotpath-allocation", "info"),
    "StaticFieldLeak": ("R-STB-004", "stability/static-context-leak", "critical"),
    "OpenForTesting": ("R-SEC-001", "security/hardcoded-secret", "info"),
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
                proc = subprocess.run(
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
            (f"R-LINT-{issue_id}", f"lint/{issue_id.lower()}", _LINT_SEV_MAP.get(issue.get("severity", "Warning"), "minor")),
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
