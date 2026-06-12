"""Detekt adapter —— P1 Kotlin 专项静态分析。

自动探测/下载 detekt-cli JAR，扫描 Kotlin 源文件，
将结果归一化为 Candidate 契约。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate

from .base import AdapterResult, EngineAdapter, ScanContext

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
_DETEKT_CONFIG = _SKILL_ROOT / "queries" / "detekt" / "detekt.yml"

# Detekt rule ID → 我们的规范 rule_id
_RULE_MAP: dict[str, tuple[str, str, str]] = {
    # (rule_id, category, severity)
    "TooGenericExceptionCaught": ("R-STB-008", "stability/swallowed-exception", "major"),
    "SwallowedException": ("R-STB-008", "stability/swallowed-exception", "major"),
    "EmptyCatchBlock": ("R-STB-008", "stability/swallowed-exception", "major"),
    "GlobalCoroutineUsage": ("R-STB-013", "stability/globalscope", "major"),
    "InjectDispatcher": ("R-STB-013", "stability/globalscope", "minor"),
    "UnnecessaryNotNullOperator": ("R-STB-012", "stability/kotlin-not-null-assert", "minor"),
    "UnsafeCallOnNullableType": ("R-STB-012", "stability/kotlin-not-null-assert", "major"),
    "NullableToStringCall": ("R-STB-012", "stability/kotlin-not-null-assert", "minor"),
    "UnsafeCast": ("R-STB-012", "stability/kotlin-not-null-assert", "major"),
    "LateinitUsage": ("R-STB-012", "stability/kotlin-not-null-assert", "minor"),
    "HardCodedStringLiteral": ("R-SEC-001", "security/hardcoded-secret", "minor"),
    "ForbiddenComment": ("R-SEC-001", "security/hardcoded-secret", "info"),
    "MaxLineLength": ("R-PRF-006", "perf/string-concat-in-loop", "info"),
    "ComplexCondition": ("R-STB-008", "stability/swallowed-exception", "minor"),
    "LongMethod": ("R-PRF-004", "perf/hotpath-allocation", "minor"),
    "NestedBlockDepth": ("R-STB-015", "stability/broken-dcl", "minor"),
    "ThreadSafeValidator": ("R-STB-030", "stability/non-threadsafe-formatter", "major"),
    "UselessCallOnNotNull": ("R-STB-012", "stability/kotlin-not-null-assert", "info"),
    "MissingWhenCase": ("R-STB-008", "stability/swallowed-exception", "major"),
    "SuspendFunWithFlowReturnType": ("R-STB-009", "stability/rxjava-disposable-leak", "major"),
}

_DEFAULT_RULE = ("R-STB-000", "stability/general", "minor")


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
            result.notes.append({"engine": self.name, "note": "作用域内无 Kotlin 文件，跳过"})
            return result

        # 确定输入目录（传给 detekt 的是目录列表）
        input_paths = list({str(ctx.repo / f.split("/")[0]) for f in kt_files})
        # 如果有多个模块目录，传全部；否则传仓库根
        if not input_paths:
            input_paths = [str(ctx.repo)]

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            report_xml = tf.name

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
            result.notes.append({"engine": self.name, "note": "Detekt 超时（300s）"})
            return result
        except Exception as e:
            result.available = False
            result.unavailable_reason = f"Detekt 运行失败: {e}"
            return result

        # Detekt 退出码: 0=无问题, 1=有问题(低于阈值), 2=有问题(超过maxIssues), 3=配置错误
        if proc.returncode == 3:
            result.available = False
            result.unavailable_reason = f"Detekt 配置错误: {(proc.stderr or proc.stdout)[:300]}"
            return result

        # 解析 XML 报告
        try:
            candidates, rules_run = _parse_xml_report(report_xml, ctx.repo, ctx.scope_files)
            result.candidates = candidates
            result.rules_run = rules_run
            result.rules_total = rules_run
        except Exception as e:
            result.notes.append({"engine": self.name, "note": f"XML 报告解析失败: {e}"})

        return result


def _find_detekt_jar() -> Path | None:
    from tools.installer import TOOLS_DIR, _DETEKT_VERSION
    jar = TOOLS_DIR / "detekt" / f"detekt-cli-{_DETEKT_VERSION}-all.jar"
    if jar.exists():
        return jar
    # 在 PATH 中查找 detekt 可执行文件（某些系统通过包管理安装）
    if shutil.which("detekt"):
        return Path(shutil.which("detekt"))
    return None


def _parse_xml_report(report_path: str, repo: Path, scope_files: list[str]) -> tuple[list[Candidate], int]:
    scope_set = set(scope_files)
    candidates: list[Candidate] = []
    rules_seen: set[str] = set()

    try:
        tree = ET.parse(report_path)
    except ET.ParseError:
        return [], 0

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
