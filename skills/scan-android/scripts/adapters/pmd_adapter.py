"""PMD adapter —— P1 Java 专项静态分析（errorprone / 多线程 / 性能）。

v3 新增：补强 Java 侧广度，尤其是 errorprone 类（如 CloseResource 资源未关闭）。
自动探测/下载 PMD CLI，运行 PMD 内置 category 规则集，归一化为 Candidate 契约。
仅处理 .java 文件（Kotlin 由 Detekt 覆盖）。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate

from .base import AdapterResult, EngineAdapter, ScanContext

# 按 check 类别选择 PMD 内置规则集（随 PMD 发行版自带，无需自写）。
# PMD 内置规则集（随发行版自带）。每次扫描全部挂上，不再按维度分。
_RULESETS = [
    "category/java/security.xml",
    "category/java/bestpractices.xml",
    "category/java/errorprone.xml",
    "category/java/multithreading.xml",
    "category/java/performance.xml",
]

# PMD ruleset → 我们的维度（用于归一化 category 前缀）
_RULESET_DIM = {
    "errorprone": "stability",
    "multithreading": "stability",
    "performance": "perf",
    "security": "security",
    "bestpractices": "stability",
}

# 高价值 PMD 规则 → 我们的规范 (rule_id, category, severity)
_RULE_MAP: dict[str, tuple[str, str, str]] = {
    "CloseResource": ("R-STB-001", "stability/resource-leak", "major"),
    "DoNotUseThreads": ("R-STB-013", "stability/raw-thread", "minor"),
    "AvoidThreadGroup": ("R-STB-013", "stability/raw-thread", "minor"),
    "UnsynchronizedStaticFormatter": ("R-STB-030", "stability/non-threadsafe-formatter", "major"),
    "AvoidUsingHardCodedIP": ("R-SEC-001", "security/hardcoded-secret", "minor"),
    "HardCodedCryptoKey": ("R-SEC-001", "security/hardcoded-secret", "critical"),
    "AvoidFileStream": ("R-PRF-001", "perf/unbuffered-file-stream", "minor"),
}

# 默认只把具备直接缺陷语义的规则送入漏洞 verifier。其余 PMD 命中仍会计入
# rules_run/suppressed/suppression_summary；配置 pmd_include_advisories=true 可全部送入。
_HIGH_SIGNAL_RULES = {
    "CloseResource",
    "UnsynchronizedStaticFormatter",
    "HardCodedCryptoKey",
}

# PMD priority 表示规则优先级，不等同安全严重性。未知规则最高只映射到 major；
# critical 仅由上方经过人工校准的安全规则显式给出。
_PRIORITY_SEV = {1: "major", 2: "major", 3: "minor", 4: "info", 5: "info"}


class PMDAdapter(EngineAdapter):
    name = "pmd"

    def is_available(self, ctx: ScanContext) -> tuple[bool, str]:
        if not shutil.which("java"):
            return False, "java 不可用（PMD 需要 JVM）"
        try:
            from tools.installer import find_pmd, ensure_pmd
            if find_pmd():
                return True, ""
            ensure_pmd()
            if find_pmd():
                return True, ""
        except Exception as e:
            return False, f"PMD 下载失败: {e}"
        return False, "PMD 不可用"

    def run(self, ctx: ScanContext) -> AdapterResult:
        result = AdapterResult(engine=self.name)
        from tools.installer import find_pmd
        pmd = find_pmd()
        if not pmd:
            result.available = False
            result.unavailable_reason = "PMD 可执行文件未找到"
            return result

        java_files = [f for f in ctx.scope_files if f.endswith(".java")]
        if not java_files:
            result.status = "not_applicable"
            result.notes.append({"engine": self.name, "note": "作用域内无 Java 文件，跳过"})
            return result

        rulesets = _RULESETS

        with tempfile.TemporaryDirectory(prefix="scan-android-pmd-") as tmp:
            file_list = Path(tmp) / "files.txt"
            file_list.write_text("\n".join(str(ctx.repo / f) for f in java_files), encoding="utf-8")
            report_json = Path(tmp) / "pmd.json"
            cmd = [
                pmd, "check",
                "--file-list", str(file_list),
                "-R", ",".join(rulesets),
                "-f", "json",
                "-r", str(report_json),
                "--no-cache",
                "--no-progress",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, cwd=str(ctx.repo))
            except subprocess.TimeoutExpired:
                result.status = "partial"
                result.notes.append({"engine": self.name, "note": "PMD 超时（600s）"})
                return result
            except Exception as e:
                result.available = False
                result.status = "failed"
                result.unavailable_reason = f"PMD 运行失败: {e}"
                return result
            # PMD 退出码：0=无违规，4=有违规，其他=错误。若报告仍存在则保留部分结果。
            if proc.returncode not in (0, 4):
                result.status = "partial"
                result.notes.append({"engine": self.name, "note": f"PMD 退出码 {proc.returncode}: {proc.stderr[:300]}"})

            try:
                data = json.loads(report_json.read_text(encoding="utf-8"))
            except Exception as e:
                result.status = "failed"
                result.notes.append({"engine": self.name, "note": f"PMD JSON 解析失败: {e}"})
                return result

        for error_key in ("processingErrors", "configurationErrors"):
            if data.get(error_key):
                result.status = "partial"
                result.notes.append({"engine": self.name, "note": f"PMD {error_key}: {str(data[error_key])[:300]}"})

        scope_set = set(ctx.scope_files)
        rule_hit: dict[str, int] = {}
        rules_seen: set[str] = set()
        include_advisories = ctx.detect_info.get("config", {}).get("pmd_include_advisories") is True
        suppressed_by_rule: dict[str, int] = {}

        for file_obj in data.get("files", []):
            path_str = file_obj.get("filename", "")
            try:
                rel = Path(path_str).resolve().relative_to(ctx.repo).as_posix()
            except ValueError:
                rel = path_str
            if scope_set and rel not in scope_set:
                continue
            for v in file_obj.get("violations", []):
                cand = _parse_violation(v, rel)
                if cand is None:
                    continue
                rules_seen.add(cand.native_rule_id)
                if not _should_emit(cand.native_rule_id, include_advisories):
                    result.suppressed += 1
                    suppressed_by_rule[cand.native_rule_id] = suppressed_by_rule.get(cand.native_rule_id, 0) + 1
                    continue
                rule_hit[cand.rule_id] = rule_hit.get(cand.rule_id, 0) + 1
                if ctx.max_per_rule > 0 and rule_hit[cand.rule_id] > ctx.max_per_rule:
                    result.truncated += 1
                    result.status = "partial"
                    if rule_hit[cand.rule_id] == ctx.max_per_rule + 1:
                        result.notes.append({
                            "rule_id": cand.rule_id,
                            "note": f"pmd: pattern-too-broad (超过 {ctx.max_per_rule} 条，已截断)",
                        })
                    continue
                result.candidates.append(cand)

        result.rules_run = len(rules_seen)
        result.rules_total = len(rules_seen)
        result.suppression_summary = dict(sorted(suppressed_by_rule.items()))
        if result.suppressed:
            result.notes.append({
                "engine": self.name,
                "note": (
                    f"PMD 高信号 profile：{result.suppressed} 条 advisory/style 命中未进入漏洞 verifier；"
                    "设置 pmd_include_advisories=true 可显式纳入"
                ),
                "suppressed_by_rule": result.suppression_summary,
            })
        return result


def _parse_violation(v: dict, rel: str) -> Candidate | None:
    rule = v.get("rule", "")
    ruleset = (v.get("ruleset", "") or "").lower()
    line = int(v.get("beginline", 0))
    end_line = int(v.get("endline", line))
    priority = int(v.get("priority", 3))
    message = (v.get("description", "") or "").strip()[:300]

    if rule in _RULE_MAP:
        rule_id, category, severity = _RULE_MAP[rule]
    else:
        dim = next((d for key, d in _RULESET_DIM.items() if key in ruleset), "stability")
        rule_id = f"R-PMD-{rule}"
        category = f"{dim}/pmd-{rule.lower()}"
        severity = _PRIORITY_SEV.get(priority, "info")

    return Candidate(
        engine="pmd",
        rule_id=rule_id,
        native_rule_id=rule,
        file=rel,
        line=line,
        end_line=end_line if end_line != line else None,
        category=category,
        severity=severity,
        message=message,
    )


def _should_emit(rule: str, include_advisories: bool = False) -> bool:
    return include_advisories or rule in _HIGH_SIGNAL_RULES
