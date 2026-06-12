"""MobSF adapter —— P4 opt-in APK 静态分析。

优先尝试连接已运行的 MobSF 实例（localhost:8000），
回退到使用 aapt2 + apktool 对 APK 做轻量本地分析。

需要设置 SCAN_ANDROID_ENABLE_MOBSF=1 才启用。
APK 路径通过 detect_info.apk_path 传入，或自动在 build/ 目录寻找。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate

from .base import AdapterResult, EngineAdapter, ScanContext

_MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000")
_MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "")

# MobSF severity → 我们的 severity
_SEV_MAP = {
    "high": "critical",
    "medium": "major",
    "warning": "major",
    "low": "minor",
    "info": "info",
    "secure": "info",
    "good": "info",
}

# MobSF issue → (rule_id, category)
_ISSUE_MAP = {
    "Debuggable Application": ("R-SEC-014", "security/debuggable-enabled"),
    "Application Data can be Backed up": ("R-SEC-015", "security/backup-allowed"),
    "Exported Activity": ("R-SEC-007", "security/exported-unprotected"),
    "Exported Service": ("R-SEC-007", "security/exported-unprotected"),
    "Exported Receiver": ("R-SEC-007", "security/exported-unprotected"),
    "Exported Provider": ("R-SEC-018", "security/exported-provider"),
    "Weak Hash Algorithm": ("R-SEC-002", "security/weak-crypto"),
    "Weak Encryption Algorithm": ("R-SEC-002", "security/weak-crypto"),
    "SSL Certificate Verification Bypass": ("R-SEC-003", "security/tls-trust-all"),
    "Cleartext HTTP Traffic": ("R-SEC-005", "security/cleartext"),
    "JavaScript Enabled": ("R-SEC-004", "security/webview"),
    "File Access Enabled": ("R-SEC-004", "security/webview"),
    "Dynamic Code Loading": ("R-SEC-019", "security/unsafe-deserialization"),
    "SQL Injection": ("R-SEC-011", "security/sql-injection"),
}


class MobSFAdapter(EngineAdapter):
    name = "mobsf"

    def is_available(self, ctx: ScanContext) -> tuple[bool, str]:
        if "mobsf" not in ctx.opt_in_engines:
            return False, "MobSF 默认关闭（在 .scan/config.json 中设置 opt_in_engines: [\"mobsf\"] 或 export SCAN_ANDROID_ENABLE_MOBSF=1）"
        apk = _find_apk(ctx)
        if not apk:
            return False, "未找到 APK 文件（需要 build/ 目录下的 debug 或 release APK）"
        # 优先检查 MobSF server
        if _ping_mobsf():
            return True, ""
        # 回退到本地 aapt2/apktool
        if shutil.which("aapt2") or shutil.which("apktool"):
            return True, ""
        # 检查 Android SDK aapt2
        aapt2 = _find_aapt2()
        if aapt2:
            return True, ""
        return False, "MobSF server 未运行且 aapt2/apktool 均未找到"

    def run(self, ctx: ScanContext) -> AdapterResult:
        result = AdapterResult(engine=self.name)
        apk = _find_apk(ctx)
        if not apk:
            result.available = False
            result.unavailable_reason = "APK 文件未找到"
            return result

        result.notes.append({"engine": self.name, "note": f"分析 APK: {apk.name}"})

        if _ping_mobsf() and _MOBSF_API_KEY:
            # 使用 MobSF REST API
            candidates = _run_mobsf_api(apk, ctx, result)
        else:
            # 使用本地 aapt2 分析（覆盖 manifest 层面问题）
            candidates = _run_local_apk_analysis(apk, ctx, result)

        result.candidates = candidates
        result.rules_run = len({c.rule_id for c in candidates})
        result.rules_total = result.rules_run
        return result


def _find_apk(ctx: ScanContext) -> Path | None:
    # 1. detect_info 显式指定
    apk_path = ctx.detect_info.get("apk_path")
    if apk_path and Path(apk_path).exists():
        return Path(apk_path)
    # 2. 自动搜索 build/outputs/apk/
    for apk in sorted(ctx.repo.rglob("*.apk")):
        if "build/outputs" in apk.as_posix():
            return apk
    return None


def _ping_mobsf() -> bool:
    try:
        with urllib.request.urlopen(f"{_MOBSF_URL}/api/v1/ping", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def _run_mobsf_api(apk: Path, ctx: ScanContext, result: AdapterResult) -> list[Candidate]:
    candidates: list[Candidate] = []
    headers = {"Authorization": _MOBSF_API_KEY}

    # 上传 APK
    try:
        with open(apk, "rb") as f:
            boundary = b"MobSFBoundary"
            body = (
                b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="file"; filename="' + apk.name.encode() + b'"\r\n'
                b"Content-Type: application/octet-stream\r\n\r\n" +
                f.read() +
                b"\r\n--" + boundary + b"--\r\n"
            )
        req = urllib.request.Request(
            f"{_MOBSF_URL}/api/v1/upload",
            data=body,
            headers={**headers, "Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            upload_resp = json.load(r)
        file_hash = upload_resp.get("hash", "")
    except Exception as e:
        result.notes.append({"engine": "mobsf", "note": f"APK 上传失败: {e}"})
        return candidates

    # 触发扫描
    try:
        req = urllib.request.Request(
            f"{_MOBSF_URL}/api/v1/scan",
            data=urllib.parse.urlencode({"hash": file_hash}).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=300) as r:
            scan_resp = json.load(r)
    except Exception as e:
        result.notes.append({"engine": "mobsf", "note": f"MobSF 扫描失败: {e}"})
        return candidates

    # 解析 manifest issues
    for issue_title, details in scan_resp.get("manifest_analysis", {}).items():
        sev = details.get("severity", "warning")
        rule_id, category = _ISSUE_MAP.get(issue_title, (f"R-MOBSF-{issue_title[:20]}", "security/general"))
        candidates.append(Candidate(
            engine="mobsf",
            rule_id=rule_id,
            native_rule_id=issue_title,
            file="AndroidManifest.xml",
            line=0,
            category=category,
            severity=_SEV_MAP.get(sev, "minor"),
            message=details.get("description", issue_title),
        ))

    # 解析代码分析 issues
    for item in scan_resp.get("code_analysis", {}).get("findings", {}).values():
        sev = item.get("metadata", {}).get("severity", "warning")
        title = item.get("metadata", {}).get("masvs", item.get("title", ""))
        rule_id, category = _ISSUE_MAP.get(title, ("R-MOBSF-CODE", "security/general"))
        for file_info in item.get("files", []):
            candidates.append(Candidate(
                engine="mobsf",
                rule_id=rule_id,
                native_rule_id=title,
                file=file_info.get("file_path", ""),
                line=int(file_info.get("match_lines", [0])[0]) if file_info.get("match_lines") else 0,
                category=category,
                severity=_SEV_MAP.get(sev, "minor"),
                message=item.get("metadata", {}).get("description", title),
            ))

    return candidates


def _run_local_apk_analysis(apk: Path, ctx: ScanContext, result: AdapterResult) -> list[Candidate]:
    """使用 aapt2 + apktool 做本地 APK 分析（manifest 层面）。"""
    candidates: list[Candidate] = []

    # aapt2 dump manifest
    aapt2 = _find_aapt2() or shutil.which("aapt2") or shutil.which("aapt")
    if not aapt2:
        result.notes.append({"engine": "mobsf", "note": "aapt2/aapt 未找到，跳过本地 APK 分析"})
        return candidates

    try:
        proc = subprocess.run(
            [aapt2, "dump", "xmltree", str(apk), "--file", "AndroidManifest.xml"],
            capture_output=True, text=True, timeout=30
        )
        manifest_text = proc.stdout
    except Exception as e:
        result.notes.append({"engine": "mobsf", "note": f"aapt2 执行失败: {e}"})
        return candidates

    # 简单检查 manifest 中的安全问题
    if "debuggable=0x1" in manifest_text or 'debuggable="true"' in manifest_text:
        candidates.append(Candidate(
            engine="mobsf", rule_id="R-SEC-014", native_rule_id="aapt2-debuggable",
            file="AndroidManifest.xml", line=0,
            category="security/debuggable-enabled", severity="critical",
            message="APK manifest: android:debuggable=true（通过 aapt2 确认）",
        ))

    if "allowBackup=0x1" in manifest_text:
        candidates.append(Candidate(
            engine="mobsf", rule_id="R-SEC-015", native_rule_id="aapt2-allowBackup",
            file="AndroidManifest.xml", line=0,
            category="security/backup-allowed", severity="major",
            message="APK manifest: android:allowBackup=true（通过 aapt2 确认）",
        ))

    if "cleartextTrafficPermitted=0x1" in manifest_text or "usesCleartextTraffic=0x1" in manifest_text:
        candidates.append(Candidate(
            engine="mobsf", rule_id="R-SEC-005", native_rule_id="aapt2-cleartext",
            file="AndroidManifest.xml", line=0,
            category="security/cleartext", severity="major",
            message="APK manifest: 允许明文 HTTP 流量（通过 aapt2 确认）",
        ))

    result.notes.append({"engine": "mobsf", "note": f"本地 aapt2 分析完成，发现 {len(candidates)} 条"})
    return candidates


def _find_aapt2() -> str | None:
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or str(
        Path.home() / "Library" / "Android" / "sdk"
    )
    for build_tools in sorted(Path(android_home).glob("build-tools/*"), reverse=True):
        candidate = build_tools / "aapt2"
        if candidate.exists():
            return str(candidate)
    return None
