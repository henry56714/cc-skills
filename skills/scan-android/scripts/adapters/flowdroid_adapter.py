"""FlowDroid adapter —— P4 opt-in APK 污点分析。

FlowDroid 是学术级 Android 污点分析工具，能追踪 source→sink 跨组件数据流。
需要 APK + Android SDK platforms 目录。

需要设置 SCAN_ANDROID_ENABLE_FLOWDROID=1 才启用。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate

from .base import AdapterResult, EngineAdapter, ScanContext

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
_SOURCES_SINKS_FILE = _SKILL_ROOT / "queries" / "flowdroid" / "SourcesAndSinks.txt"


class FlowDroidAdapter(EngineAdapter):
    name = "flowdroid"

    def is_available(self, ctx: ScanContext) -> tuple[bool, str]:
        if "flowdroid" not in ctx.opt_in_engines:
            return False, "FlowDroid 默认关闭（在 .scan/config.json 中设置 opt_in_engines: [\"flowdroid\"] 或 export SCAN_ANDROID_ENABLE_FLOWDROID=1）"
        if not shutil.which("java"):
            return False, "FlowDroid 需要 Java"
        apk = _find_apk(ctx)
        if not apk:
            return False, "未找到 APK 文件"
        platforms = _find_android_platforms()
        if not platforms:
            return False, "未找到 Android SDK platforms 目录"
        jar = _find_flowdroid_jar()
        if jar:
            return True, ""
        # 自动下载
        try:
            from tools.installer import ensure_flowdroid
            path, _ = ensure_flowdroid()
            if path and Path(path).exists():
                return True, ""
        except Exception as e:
            return False, f"FlowDroid JAR 下载失败: {e}"
        return False, "FlowDroid JAR 不可用"

    def run(self, ctx: ScanContext) -> AdapterResult:
        result = AdapterResult(engine=self.name)
        jar = _find_flowdroid_jar()
        apk = _find_apk(ctx)
        platforms = _find_android_platforms()

        if not jar or not apk or not platforms:
            result.available = False
            result.unavailable_reason = "FlowDroid 依赖不满足（jar/apk/platforms）"
            return result

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            out_xml = tf.name

        # 构建 SourcesAndSinks.txt（如果不存在用内置默认）
        ss_file = _ensure_sources_sinks()

        cmd = [
            "java", "-Xmx4g",
            "-jar", str(jar),
            "-a", str(apk),
            "-p", str(platforms),
            "-s", str(ss_file),
            "-o", out_xml,
            "-t", "120",  # 超时 120 秒
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=str(ctx.repo),
            )
        except subprocess.TimeoutExpired:
            result.notes.append({"engine": self.name, "note": "FlowDroid 超时（180s）"})
            Path(out_xml).unlink(missing_ok=True)
            return result
        except Exception as e:
            result.available = False
            result.unavailable_reason = f"FlowDroid 运行失败: {e}"
            Path(out_xml).unlink(missing_ok=True)
            return result

        # 解析 XML 输出
        try:
            candidates = _parse_flowdroid_output(out_xml, ctx)
            result.candidates = candidates
            result.rules_run = len({c.rule_id for c in candidates})
            result.rules_total = result.rules_run
        except Exception as e:
            result.notes.append({"engine": self.name, "note": f"FlowDroid 结果解析失败: {e}"})
        finally:
            Path(out_xml).unlink(missing_ok=True)

        return result


def _find_apk(ctx: ScanContext) -> Path | None:
    apk_path = ctx.detect_info.get("apk_path")
    if apk_path and Path(apk_path).exists():
        return Path(apk_path)
    for apk in sorted(ctx.repo.rglob("*.apk")):
        if "build/outputs" in apk.as_posix():
            return apk
    return None


def _find_android_platforms() -> Path | None:
    candidates = [
        Path(os.environ.get("ANDROID_HOME", "")) / "platforms",
        Path(os.environ.get("ANDROID_SDK_ROOT", "")) / "platforms",
        Path.home() / "Library" / "Android" / "sdk" / "platforms",
        Path("/usr/local/share/android-sdk/platforms"),
    ]
    for c in candidates:
        if c.exists() and any(c.iterdir()):
            return c
    return None


def _find_flowdroid_jar() -> Path | None:
    try:
        from tools.installer import TOOLS_DIR, _FLOWDROID_VERSION
        jar = TOOLS_DIR / "flowdroid" / f"flowdroid-{_FLOWDROID_VERSION}.jar"
        if jar.exists():
            return jar
    except Exception:
        pass
    return None


def _ensure_sources_sinks() -> Path:
    if _SOURCES_SINKS_FILE.exists():
        return _SOURCES_SINKS_FILE
    # 使用内置的简化版本
    ss_dir = _SOURCES_SINKS_FILE.parent
    ss_dir.mkdir(parents=True, exist_ok=True)
    content = """\
# FlowDroid Sources and Sinks for scan-android
# Sources: user-controlled input
<android.content.Intent: java.lang.String getStringExtra(java.lang.String)> -> _SOURCE_
<android.content.Intent: android.os.Bundle getExtras()> -> _SOURCE_
<android.content.Intent: java.io.Serializable getSerializableExtra(java.lang.String)> -> _SOURCE_
<android.telephony.TelephonyManager: java.lang.String getDeviceId()> -> _SOURCE_
<android.location.Location: double getLatitude()> -> _SOURCE_
<android.location.Location: double getLongitude()> -> _SOURCE_

# Sinks: dangerous operations
<android.database.sqlite.SQLiteDatabase: android.database.Cursor rawQuery(java.lang.String,java.lang.String[])> -> _SINK_
<android.database.sqlite.SQLiteDatabase: void execSQL(java.lang.String)> -> _SINK_
<java.lang.Runtime: java.lang.Process exec(java.lang.String)> -> _SINK_
<java.lang.ProcessBuilder: java.lang.ProcessBuilder command(java.lang.String[])> -> _SINK_
<android.util.Log: int d(java.lang.String,java.lang.String)> -> _SINK_
<android.util.Log: int i(java.lang.String,java.lang.String)> -> _SINK_
<android.util.Log: int w(java.lang.String,java.lang.String)> -> _SINK_
<android.util.Log: int e(java.lang.String,java.lang.String)> -> _SINK_
"""
    _SOURCES_SINKS_FILE.write_text(content, encoding="utf-8")
    return _SOURCES_SINKS_FILE


def _parse_flowdroid_output(xml_path: str, ctx: ScanContext) -> list[Candidate]:
    """解析 FlowDroid XML 结果。"""
    candidates: list[Candidate] = []
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        return candidates

    root = tree.getroot()
    scope_set = set(ctx.scope_files)

    for flow in root.findall(".//flow"):
        source_elem = flow.find("source")
        sink_elem = flow.find("sink")
        if source_elem is None or sink_elem is None:
            continue

        source_method = source_elem.get("method", "")
        sink_method = sink_elem.get("method", "")
        sink_file = sink_elem.get("File", "")
        sink_line = int(sink_elem.get("Line", 0))

        # 转相对路径
        try:
            rel = Path(sink_file).resolve().relative_to(ctx.repo).as_posix()
        except ValueError:
            rel = sink_file
        if scope_set and rel not in scope_set:
            continue

        # 推断规则
        rule_id, category = _classify_flow(source_method, sink_method)
        severity = "critical" if "SQL" in category or "injection" in category else "major"

        dataflow_path = [
            {"file": source_elem.get("File", ""), "line": int(source_elem.get("Line", 0)), "message": f"来源: {source_method}"},
            {"file": sink_file, "line": sink_line, "message": f"汇聚点: {sink_method}"},
        ]

        candidates.append(Candidate(
            engine="flowdroid",
            rule_id=rule_id,
            native_rule_id=f"fd-{source_method.split('.')[-1]}-{sink_method.split('.')[-1]}",
            file=rel,
            line=sink_line,
            category=category,
            severity=severity,
            message=f"FlowDroid 污点路径: {source_method} → {sink_method}",
            dataflow_path=dataflow_path,
        ))

    return candidates


def _classify_flow(source: str, sink: str) -> tuple[str, str]:
    if "rawQuery" in sink or "execSQL" in sink:
        return "R-SEC-011", "security/sql-injection"
    if "exec" in sink or "ProcessBuilder" in sink:
        return "R-SEC-012", "security/command-injection"
    if "Log." in sink:
        return "R-SEC-010", "security/log-leakage"
    return "R-FD-TAINT", "security/general"
