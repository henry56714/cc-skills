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
}

# PMD priority(1 最高 .. 5 最低) → severity
_PRIORITY_SEV = {1: "critical", 2: "major", 3: "minor", 4: "info", 5: "info"}


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
            result.notes.append({"engine": self.name, "note": "作用域内无 Java 文件，跳过"})
            return result

        rulesets = _RULESETS

        # 把作用域内 java 文件写入 file-list，精确限定 PMD 扫描范围
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as flf:
            flf.write("\n".join(str(ctx.repo / f) for f in java_files))
            file_list = flf.name
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as rf:
            report_json = rf.name

        cmd = [
            pmd, "check",
            "--file-list", file_list,
            "-R", ",".join(rulesets),
            "-f", "json",
            "-r", report_json,
            "--no-cache",
            "--no-progress",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600, cwd=str(ctx.repo))
        except subprocess.TimeoutExpired:
            result.notes.append({"engine": self.name, "note": "PMD 超时（600s）"})
            return result
        except Exception as e:
            result.available = False
            result.unavailable_reason = f"PMD 运行失败: {e}"
            return result
        # PMD 退出码：0=无违规，4=有违规，其他=错误。两者都正常解析报告。

        try:
            with open(report_json, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            result.notes.append({"engine": self.name, "note": f"PMD JSON 解析失败: {e}"})
            return result

        scope_set = set(ctx.scope_files)
        rule_hit: dict[str, int] = {}
        rules_seen: set[str] = set()

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
                rule_hit[cand.rule_id] = rule_hit.get(cand.rule_id, 0) + 1
                if rule_hit[cand.rule_id] > ctx.max_per_rule:
                    if rule_hit[cand.rule_id] == ctx.max_per_rule + 1:
                        result.notes.append({
                            "rule_id": cand.rule_id,
                            "note": f"pmd: pattern-too-broad (超过 {ctx.max_per_rule} 条，已截断)",
                        })
                    continue
                result.candidates.append(cand)

        result.rules_run = len(rules_seen)
        result.rules_total = len(rules_seen)
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
