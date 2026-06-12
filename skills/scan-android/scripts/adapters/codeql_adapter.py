"""CodeQL adapter —— P4 opt-in，需要 GitHub Advanced Security 许可。

对私有/商业代码做自动化 CodeQL 分析前请确认已持有合法许可。
自动探测/下载 CodeQL CLI，构建数据库，运行查询，归一化为 Candidate。

降级: CodeQL 不可用或无许可 → 跳过（其他引擎已覆盖大部分规则）
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate

from .base import AdapterResult, EngineAdapter, InstallationError, ScanContext

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
_CODEQL_QUERY_DIR = _SKILL_ROOT / "queries" / "codeql"
_CODEQL_DB_DIR = Path(".scan") / "codeql_db"

# CodeQL severity → 我们的 severity
_SEV_MAP = {
    "error": "critical",
    "warning": "major",
    "recommendation": "minor",
    "note": "info",
}


class CodeQLAdapter(EngineAdapter):
    name = "codeql"

    def is_available(self, ctx: ScanContext) -> tuple[bool, str]:
        # 默认关闭（opt-in）：未显式启用时静默跳过，不影响扫描
        if "codeql" not in ctx.opt_in_engines:
            return False, "CodeQL 默认关闭（在 .scan/config.json 中设置 opt_in_engines: [\"codeql\"] 或 export SCAN_ANDROID_ENABLE_CODEQL=1）"
        codeql = _find_codeql()
        if codeql:
            return True, ""
        # 已在 opt_in_engines 中配置 → 必须安装成功；失败则中止扫描
        try:
            from tools.installer import ensure_codeql
            path, _ = ensure_codeql()
            if path and Path(path).exists():
                return True, ""
        except Exception as e:
            raise InstallationError(
                f"CodeQL 已在 opt_in_engines 中配置，但安装失败（已重试多次）: {e}\n"
                "请检查网络连接或代理设置后重新运行扫描。\n"
                "若要在无 CodeQL 的情况下继续，请将 \"codeql\" 从 .scan/config.json "
                "的 opt_in_engines 中移除。"
            ) from e
        raise InstallationError("CodeQL CLI 安装后仍未找到，请手动检查安装目录。")

    def run(self, ctx: ScanContext) -> AdapterResult:
        result = AdapterResult(engine=self.name)
        codeql = _find_codeql()
        if not codeql:
            result.available = False
            result.unavailable_reason = "CodeQL CLI 未找到"
            return result

        # 构建 CodeQL 数据库
        db_path = ctx.repo / _CODEQL_DB_DIR
        built = _build_database(codeql, ctx.repo, db_path, result)
        if not built:
            result.available = False
            result.unavailable_reason = "CodeQL 数据库构建失败"
            return result

        # 运行查询
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tf:
            sarif_out = tf.name

        cmd = [
            codeql, "database", "analyze",
            str(db_path),
            str(_CODEQL_QUERY_DIR),
            "--format=sarif-latest",
            f"--output={sarif_out}",
            "--threads=0",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(ctx.repo),
            )
            if proc.returncode != 0:
                result.notes.append({
                    "engine": self.name,
                    "note": f"CodeQL analyze 失败(rc={proc.returncode}): {proc.stderr[:1000]}",
                })
                Path(sarif_out).unlink(missing_ok=True)
                return result
        except subprocess.TimeoutExpired:
            result.notes.append({"engine": self.name, "note": "CodeQL analyze 超时（600s）"})
            Path(sarif_out).unlink(missing_ok=True)
            return result
        except Exception as e:
            result.available = False
            result.unavailable_reason = f"CodeQL 运行失败: {e}"
            Path(sarif_out).unlink(missing_ok=True)
            return result

        # 解析 SARIF 输出
        sarif_path = Path(sarif_out)
        if not sarif_path.exists() or sarif_path.stat().st_size == 0:
            result.notes.append({"engine": self.name, "note": "CodeQL analyze 成功但 SARIF 输出为空（0 结果）"})
            sarif_path.unlink(missing_ok=True)
            return result

        try:
            scope_set = set(ctx.scope_files)
            candidates, rules_run = _parse_sarif(sarif_out, ctx.repo, scope_set)
            result.candidates = candidates
            result.rules_run = rules_run
            result.rules_total = rules_run
        except Exception as e:
            result.notes.append({"engine": self.name, "note": f"SARIF 解析失败: {e}"})
        finally:
            sarif_path.unlink(missing_ok=True)

        return result


def _find_codeql() -> str | None:
    existing = shutil.which("codeql")
    if existing:
        return existing
    try:
        from tools.installer import TOOLS_DIR
        local = TOOLS_DIR / "codeql" / "codeql"
        if local.exists():
            return str(local)
    except Exception:
        pass
    return None


def _build_database(codeql: str, repo: Path, db_path: Path, result: AdapterResult) -> bool:
    """构建 CodeQL 数据库。优先用 Gradle 构建，回退到 --build-mode=none。"""
    if db_path.exists():
        result.notes.append({"engine": "codeql", "note": "复用已有 CodeQL 数据库"})
        return True

    db_path.parent.mkdir(parents=True, exist_ok=True)

    # 尝试 Gradle 构建
    gradlew = repo / "gradlew"
    if gradlew.exists():
        cmd = [
            codeql, "database", "create",
            str(db_path),
            "--language=java",
            f"--source-root={repo}",
            "--command=./gradlew compileDebugJavaWithJavac compileDebugKotlin --no-daemon",
            "--overwrite",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600, cwd=str(repo)
            )
            if proc.returncode == 0 and db_path.exists():
                return True
        except Exception:
            pass

    # 回退到 source-only 模式
    cmd = [
        codeql, "database", "create",
        str(db_path),
        "--language=java",
        f"--source-root={repo}",
        "--build-mode=none",
        "--overwrite",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, cwd=str(repo)
        )
        if proc.returncode == 0 and db_path.exists():
            result.notes.append({"engine": "codeql", "note": "CodeQL 数据库使用 source-only 模式构建（无编译）"})
            return True
        result.notes.append({
            "engine": "codeql",
            "note": f"CodeQL 数据库构建失败: {proc.stderr[:300]}",
        })
        return False
    except Exception as e:
        result.notes.append({"engine": "codeql", "note": f"CodeQL 数据库构建异常: {e}"})
        return False


def _parse_sarif(sarif_path: str, repo: Path, scope_set: set[str]) -> tuple[list[Candidate], int]:
    """解析 SARIF 格式的 CodeQL 输出。"""
    with open(sarif_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    candidates: list[Candidate] = []
    rules_seen: set[str] = set()

    for run in data.get("runs", []):
        # 构建规则 ID → metadata 映射
        rule_meta: dict[str, dict] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rule_meta[rule["id"]] = rule.get("properties", {})

        for result in run.get("results", []):
            rule_id_native = result.get("ruleId", "")
            rules_seen.add(rule_id_native)

            # 从规则 ID 推断我们的规范 ID
            rule_id = _infer_rule_id(rule_id_native)
            sev_raw = result.get("level", "warning")
            severity = _SEV_MAP.get(sev_raw, "minor")

            message = result.get("message", {}).get("text", "")

            # 提取 dataflow_path（CodeQL path-problem 查询）
            dataflow: list[dict] = []
            for location in result.get("codeFlows", [{}])[0].get("threadFlows", [{}])[0].get("locations", []):
                pl = location.get("location", {}).get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                ln = pl.get("region", {}).get("startLine", 0)
                msg_step = location.get("message", {}).get("text", "")
                try:
                    rel_step = Path(uri).relative_to(repo).as_posix()
                except ValueError:
                    rel_step = uri
                dataflow.append({"file": rel_step, "line": ln, "message": msg_step})

            # 主位置
            for location in result.get("locations", []):
                pl = location.get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                region = pl.get("region", {})
                line = region.get("startLine", 0)
                try:
                    rel = Path(uri).relative_to(repo).as_posix()
                except ValueError:
                    rel = uri

                if scope_set and rel not in scope_set:
                    continue

                category = _infer_category(rule_id)
                candidates.append(Candidate(
                    engine="codeql",
                    rule_id=rule_id,
                    native_rule_id=rule_id_native,
                    file=rel,
                    line=line,
                    category=category,
                    severity=severity,
                    message=message,
                    dataflow_path=dataflow,
                ))

    return candidates, len(rules_seen)


def _infer_rule_id(native_id: str) -> str:
    mapping = {
        "AndroidSqlInjection": "R-SEC-011",
        "CommandInjection": "R-SEC-012",
        "IntentRedirection": "R-SEC-016",
        "UnsafeDeserialization": "R-SEC-019",
        "WeakCryptographicAlgorithm": "R-SEC-002",
        "HardcodedCredentialsApiCall": "R-SEC-001",
        "CleartextStorageAndroid": "R-SEC-020",
        "InsecureTrustManager": "R-SEC-003",
    }
    return mapping.get(native_id, f"R-CQL-{native_id}")


def _infer_category(rule_id: str) -> str:
    cat_map = {
        "R-SEC-001": "security/hardcoded-secret",
        "R-SEC-002": "security/weak-crypto",
        "R-SEC-003": "security/tls-trust-all",
        "R-SEC-011": "security/sql-injection",
        "R-SEC-012": "security/command-injection",
        "R-SEC-016": "security/intent-redirection",
        "R-SEC-019": "security/unsafe-deserialization",
        "R-SEC-020": "security/sensitive-external-storage",
    }
    return cat_map.get(rule_id, "security/general")
