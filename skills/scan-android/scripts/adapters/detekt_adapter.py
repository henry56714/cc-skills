"""Detekt adapter —— P1 Kotlin 专项静态分析。

自动探测/下载 detekt-cli JAR，扫描 Kotlin 源文件，
将结果归一化为 Candidate 契约。
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate

from .base import AdapterResult, EngineAdapter, ScanContext

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
_DETEKT_CONFIG = _SKILL_ROOT / "queries" / "detekt" / "detekt.yml"

# Detekt rule ID → 我们的规范 rule_id
_RULE_MAP: dict[str, tuple[str, str, str]] = {
    # (rule_id, category, severity)
    "TooGenericExceptionCaught": ("R-DK-001", "stability/swallowed-exception", "major"),
    "SwallowedException": ("R-DK-001", "stability/swallowed-exception", "major"),
    "EmptyCatchBlock": ("R-DK-001", "stability/swallowed-exception", "major"),
    "GlobalCoroutineUsage": ("R-DK-002", "stability/globalscope", "major"),
    "InjectDispatcher": ("R-DK-002", "stability/globalscope", "minor"),
    "SleepInsteadOfDelay": ("R-DK-002", "stability/blocking-call-in-coroutine", "major"),
    "SuspendFunWithFlowReturnType": ("R-DK-002", "stability/coroutine-api-misuse", "minor"),
    "UnnecessaryNotNullOperator": ("R-DK-003", "stability/kotlin-not-null-assert", "minor"),
    "UnsafeCallOnNullableType": ("R-DK-003", "stability/kotlin-not-null-assert", "major"),
    "NullableToStringCall": ("R-DK-003", "stability/kotlin-not-null-assert", "minor"),
    "UnsafeCast": ("R-DK-003", "stability/kotlin-not-null-assert", "major"),
    "LateinitUsage": ("R-DK-003", "stability/kotlin-not-null-assert", "minor"),
    "UselessCallOnNotNull": ("R-DK-003", "stability/kotlin-not-null-assert", "info"),
    "ForbiddenComment": ("R-DK-004", "security/hardcoded-secret", "info"),
    "HasPlatformType": ("R-DK-005", "stability/platform-type", "minor"),
    "UnreachableCode": ("R-DK-006", "stability/unreachable-code", "minor"),
    "InvalidRange": ("R-DK-007", "stability/invalid-range", "major"),
    "IteratorHasNextCallsNextMethod": ("R-DK-008", "stability/iterator-contract", "major"),
    "IteratorNotThrowingNoSuchElementException": ("R-DK-008", "stability/iterator-contract", "major"),
    "MapGetWithNotNullAssertionOperator": ("R-DK-003", "stability/kotlin-not-null-assert", "major"),
    "UnconditionalJumpStatementInLoop": ("R-DK-009", "stability/loop-control", "minor"),
    "WrongEqualsTypeParameter": ("R-DK-010", "stability/equals-contract", "major"),
}

_DEFAULT_RULE = ("R-DK-000", "stability/general", "minor")


class DetektAdapter(EngineAdapter):
    name = "detekt"

    def is_available(self, ctx: ScanContext) -> tuple[bool, str]:
        java_ok = bool(shutil.which("java"))
        if not java_ok:
            return False, "java 不可用（Detekt 需要 JVM）"
        jar = _find_detekt_jar()
        if jar:
            return True, ""
        # 自动下载
        try:
            from tools.installer import ensure_detekt
            ensure_detekt()
            if _find_detekt_jar():
                return True, ""
        except Exception as e:
            return False, f"Detekt JAR 下载失败: {e}"
        return False, "Detekt JAR 不可用"

    def run(self, ctx: ScanContext) -> AdapterResult:
        result = AdapterResult(engine=self.name)
        jar = _find_detekt_jar()
        if not jar:
            result.available = False
            result.unavailable_reason = "Detekt JAR 未找到"
            return result

        # 只处理 Kotlin 文件
        kt_files = [f for f in ctx.scope_files if f.endswith(".kt")]
        if not kt_files:
            result.status = "not_applicable"
            result.notes.append({"engine": self.name, "note": "作用域内无 Kotlin 文件，跳过"})
            return result

        # 直接传入 scope 内的 Kotlin 文件（绝对路径），避免扫描整个模块目录
        input_paths = [str(ctx.repo / f) for f in kt_files]

        with tempfile.TemporaryDirectory(prefix="scan-android-detekt-") as tmp:
            report_xml = str(Path(tmp) / "detekt.xml")
            cmd = [
                "java", "-jar", str(jar),
                "--input", ",".join(input_paths),
                "--report", f"xml:{report_xml}",
            ]
            if _DETEKT_CONFIG.exists():
                cmd += ["--config", str(_DETEKT_CONFIG)]
            cmd += ["--jvm-target", "11"]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=str(ctx.repo),
                )
            except subprocess.TimeoutExpired:
                result.status = "partial"
                result.notes.append({"engine": self.name, "note": "Detekt 超时（300s）"})
                return result
            except Exception as e:
                result.available = False
                result.status = "failed"
                result.unavailable_reason = f"Detekt 运行失败: {e}"
                return result

            # Detekt CLI: 0=正常且未超阈值，2=规则命中超过 maxIssues；1=异常，3=配置错误。
            if proc.returncode not in (0, 2):
                result.status = "failed" if proc.returncode == 3 else "partial"
                result.notes.append({
                    "engine": self.name,
                    "note": f"Detekt 退出码 {proc.returncode}: {(proc.stderr or proc.stdout)[:300]}",
                })
                if proc.returncode == 3:
                    result.available = False
                    result.unavailable_reason = "Detekt 配置校验失败"
                    return result

            try:
                candidates, rules_run = _parse_xml_report(report_xml, ctx.repo, ctx.scope_files)
                result.candidates = candidates
                result.rules_run = rules_run
                result.rules_total = rules_run
            except Exception as e:
                result.status = "failed"
                result.notes.append({"engine": self.name, "note": f"XML 报告解析失败: {e}"})

        return result


def _find_detekt_jar() -> Path | None:
    from tools.installer import TOOLS_DIR, _DETEKT_VERSION
    jar = TOOLS_DIR / "detekt" / f"detekt-cli-{_DETEKT_VERSION}-all.jar"
    if jar.exists() and zipfile.is_zipfile(jar):
        return jar
    return None


def _parse_xml_report(report_path: str, repo: Path, scope_files: list[str]) -> tuple[list[Candidate], int]:
    repo = repo.resolve()
    scope_set = set(scope_files)
    candidates: list[Candidate] = []
    rules_seen: set[str] = set()

    tree = ET.parse(report_path)

    root = tree.getroot()
    # Detekt XML 格式: <checkstyle> → <file name="..."> → <error line="..." source="..." message="..."/>
    for file_elem in root.findall("file"):
        path_str = file_elem.get("name", "")
        try:
            rel = Path(path_str).resolve().relative_to(repo).as_posix()
        except ValueError:
            rel = path_str
        if scope_set and rel not in scope_set:
            continue

        for error_elem in file_elem.findall("error"):
            native_rule = error_elem.get("source", "")
            # source 格式: "detekt.StyleGuide.FunctionName"
            rule_short = native_rule.rsplit(".", 1)[-1] if "." in native_rule else native_rule
            rules_seen.add(rule_short)

            rule_id, category, severity = _RULE_MAP.get(rule_short, _DEFAULT_RULE)
            line = int(error_elem.get("line", 0))
            message = error_elem.get("message", "")
            sev_raw = error_elem.get("severity", "warning")
            if rule_id == _DEFAULT_RULE[0]:
                # 未知规则：用 Detekt 自己的 severity
                severity = {"error": "major", "warning": "minor", "info": "info"}.get(sev_raw, "info")

            candidates.append(Candidate(
                engine="detekt",
                rule_id=rule_id,
                native_rule_id=native_rule,
                file=rel,
                line=line,
                category=category,
                severity=severity,
                message=message,
            ))

    return candidates, len(rules_seen)
