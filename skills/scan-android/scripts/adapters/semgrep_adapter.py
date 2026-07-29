"""Semgrep adapter —— P1 广度扫描引擎（AST 感知，比纯正则精确）。

自动探测 semgrep 是否可用；未安装则通过 pip 自动安装。
规则来源（v3）：
- **社区 registry 规则包**（广度主力，数千条）：按 check 类别挂 `p/...` 包；
- **本地自写规则** `queries/semgrep/`：只补社区库未覆盖的 Android/项目特定缺口。
两者结果统一归一化为 Candidate 契约。为保证可复现并避免扫描时隐式联网，registry
默认关闭；需要时在 `.scan/config.json` 显式设置 `semgrep_use_registry:true`。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate

from .base import AdapterResult, EngineAdapter, ScanContext

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
_QUERIES_DIR = _SKILL_ROOT / "queries" / "semgrep"

# Semgrep severity → 我们的 severity
_SEV_MAP = {
    "ERROR": "critical",
    "WARNING": "major",
    "INFO": "minor",
    "INVENTORY": "info",
    "EXPERIMENT": "info",
}

# 社区 registry 规则包（v3：广度主力杠杆）。每次扫描全部挂上——
# 安全/OWASP/密钥 + 语言通用（p/java、p/kotlin）。不再按维度分。
_DEFAULT_REGISTRY_PACKS = [
    "p/security-audit", "p/owasp-top-ten", "p/secrets", "p/java", "p/kotlin",
]


def _load_semgrep_config(repo: Path) -> tuple[bool, list[str] | None]:
    """读取 .scan/config.json 的 semgrep 配置。

    返回 (use_registry, packs_override)：
    - use_registry: 默认 False；显式授权联网拉取规则包时设 true。
    - packs_override: 显式覆盖默认 registry 包清单；None = 用默认全集。
    """
    cfg: dict = {}
    p = repo / ".scan" / "config.json"
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                cfg = loaded if isinstance(loaded, dict) else {}
        except Exception:
            pass
    use_registry = cfg.get("semgrep_use_registry", False) is True
    packs = cfg.get("semgrep_registry_packs")
    if isinstance(packs, list) and packs:
        return use_registry, [str(x) for x in packs]
    return use_registry, None


class SemgrepAdapter(EngineAdapter):
    name = "semgrep"

    def is_available(self, ctx: ScanContext) -> tuple[bool, str]:
        semgrep = _find_semgrep()
        if semgrep:
            return True, ""
        # 尝试自动安装
        try:
            from tools.installer import ensure_semgrep
            path, _ = ensure_semgrep()
            if path:
                return True, ""
        except Exception as e:
            return False, f"semgrep 安装失败: {e}"
        return False, "semgrep 不可用且安装失败"

    def run(self, ctx: ScanContext) -> AdapterResult:
        result = AdapterResult(engine=self.name)
        semgrep = _find_semgrep()
        if not semgrep:
            result.available = False
            result.unavailable_reason = "semgrep 可执行文件未找到"
            return result

        if not _QUERIES_DIR.exists():
            result.available = False
            result.unavailable_reason = f"Semgrep 规则目录不存在: {_QUERIES_DIR}"
            return result

        # 本地自写规则：queries/semgrep/ 下的全部 yaml（只补社区库未覆盖的缺口）
        rule_files = sorted(_QUERIES_DIR.glob("*.yaml"))

        # 社区 registry 规则包需显式开启，避免隐式联网与规则漂移。
        use_registry, packs_override = _load_semgrep_config(ctx.repo)
        registry_packs = (packs_override if packs_override is not None else _DEFAULT_REGISTRY_PACKS) if use_registry else []

        if not rule_files and not registry_packs:
            result.notes.append({"engine": self.name, "note": "没有匹配的 semgrep 规则（本地 + registry 均为空）"})
            return result

        # 构建 semgrep 命令：本地规则 + 社区 registry 包
        cmd = [
            semgrep, "--json", "--quiet", "--no-git-ignore", "--dataflow-traces",
            "--metrics", "off", "--disable-version-check", "--project-root", ".",
            # Scope/excludes 由 prepare_scope + 结果过滤统一决定，目标仓库不能用
            # .semgrepignore 静默隐藏代码；大于 Semgrep 默认 1 MB 的源文件也不能静默跳过。
            "--x-ignore-semgrepignore-files", "--max-target-bytes", "0",
        ]
        for rf in rule_files:
            cmd += ["--config", str(rf)]
        for pack in registry_packs:
            cmd += ["--config", pack]

        # 溯源：记录本次实际用的规则来源，供报告头展示（v3 §3：规则供给写入报告头）
        result.notes.append({
            "engine": self.name,
            "note": "semgrep 规则来源",
            "local_rules": [rf.name for rf in rule_files],
            "registry_packs": registry_packs,
        })

        # cwd 已是仓库根。使用 "." 避免 Semgrep 默认 ignore 规则误把仓库祖先目录
        # （例如 /work/tests/project）当成仓库内路径并整仓跳过。
        cmd.append(".")

        try:
            env = os.environ.copy()
            env.setdefault("SEMGREP_SEND_METRICS", "off")
            env.setdefault("SEMGREP_LOG_FILE", str(ctx.repo / ".scan" / "tmp" / "semgrep.log"))
            if not env.get("SSL_CERT_FILE"):
                for cert in sorted(Path(semgrep).parent.parent.glob("lib/python*/site-packages/certifi/cacert.pem")):
                    env["SSL_CERT_FILE"] = str(cert)
                    break
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(ctx.repo),
                env=env,
            )
        except subprocess.TimeoutExpired:
            result.status = "partial"
            result.notes.append({"engine": self.name, "note": "semgrep 超时（600s），未产生可验证的完整结果"})
            return result
        except Exception as e:
            result.available = False
            result.status = "failed"
            result.unavailable_reason = f"semgrep 运行失败: {e}"
            return result

        # semgrep --json 的退出码：0=无发现，1=有发现，2=错误
        if proc.returncode not in (0, 1):
            result.status = "partial"
            result.notes.append({
                "engine": self.name,
                "note": f"semgrep 退出码 {proc.returncode}，stderr: {proc.stderr[:500]}",
            })
            if not proc.stdout.strip():
                result.available = False
                result.status = "failed"
                result.unavailable_reason = "semgrep 返回空结果（可能出错）"
                return result

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            result.status = "failed"
            result.notes.append({"engine": self.name, "note": f"semgrep JSON 解析失败: {e}"})
            return result

        # 解析结果
        scope_set = set(ctx.scope_files)
        rule_hit_count: dict[str, int] = {}

        parse_failures = 0
        for item in data.get("results", []):
            try:
                candidate = _parse_result(item, ctx.repo, scope_set)
            except Exception:
                parse_failures += 1
                continue
            if candidate is None:
                continue
            rule_id = candidate.rule_id
            rule_hit_count[rule_id] = rule_hit_count.get(rule_id, 0) + 1
            if ctx.max_per_rule > 0 and rule_hit_count[rule_id] > ctx.max_per_rule:
                result.truncated += 1
                result.status = "partial"
                if rule_hit_count[rule_id] == ctx.max_per_rule + 1:
                    result.notes.append({
                        "rule_id": rule_id,
                        "note": f"semgrep: pattern-too-broad (超过 {ctx.max_per_rule} 条，已截断)",
                    })
                continue
            result.candidates.append(candidate)

        # 统计规则数
        check_ids = {item.get("check_id", "") for item in data.get("results", [])}
        result.rules_run = len(check_ids)
        result.rules_total = len(check_ids)

        # 记录 semgrep 的错误/警告
        for err in data.get("errors", []):
            result.status = "partial"
            result.notes.append({"engine": self.name, "note": f"semgrep error: {err.get('message', '')}"})
        if parse_failures:
            result.status = "partial"
            result.notes.append({"engine": self.name, "note": f"{parse_failures} 条 Semgrep 结果解析失败"})

        return result


def _find_semgrep() -> str | None:
    # 只接受 scan-android 管理的固定版本，避免 PATH/旧 venv 让规则语义漂移。
    try:
        from tools.installer import _SEMGREP_VERSION, _venv_package_version, venv_bin
        venv_semgrep = venv_bin("semgrep")
        if (
            Path(venv_semgrep).exists()
            and _venv_package_version("semgrep") == _SEMGREP_VERSION
        ):
            return venv_semgrep
    except Exception:
        pass
    return None


def _parse_result(item: dict, repo: Path, scope_set: set[str]) -> Candidate | None:
    path_str = item.get("path", "")
    # 转为相对路径
    try:
        rel = Path(path_str).resolve().relative_to(repo).as_posix()
    except ValueError:
        # 可能已是相对路径
        rel = path_str
    # 如果 scope_set 非空，只保留作用域内文件
    if scope_set and rel not in scope_set:
        return None

    check_id = item.get("check_id", "")
    start = item.get("start", {})
    line = int(start.get("line", 0))
    end_line = int(item.get("end", {}).get("line", line))
    extra = item.get("extra", {})
    message = extra.get("message", "")
    sev_raw = extra.get("severity", "INFO")

    # 从规则 metadata 提取我们的规范信息
    metadata = extra.get("metadata", {})
    rule_id = metadata.get("rule_id", "") or _infer_rule_id(check_id)
    category = metadata.get("category", "") or extra.get("metadata", {}).get("category", "")
    severity = metadata.get("severity", "") or _SEV_MAP.get(sev_raw, "info")

    snippet = extra.get("lines", "").strip()

    # semgrep 免费版的 lines 字段会返回 "requires login"，此时从源文件读取
    if snippet == "requires login" or not snippet:
        snippet = _read_snippet_from_file(repo, rel, line, end_line)

    snippet = snippet[:300]
    dataflow_path = _extract_dataflow_path(extra, repo)

    return Candidate(
        engine="semgrep",
        rule_id=rule_id,
        native_rule_id=check_id,
        file=rel,
        line=line,
        end_line=end_line if end_line != line else None,
        category=category,
        severity=severity,
        snippet=snippet,
        message=message,
        dataflow_path=dataflow_path,
    )


def _extract_dataflow_path(extra: dict, repo: Path) -> list[dict]:
    """把 Semgrep taint 的 dataflow_trace 归一化为 source→sink 节点。

    Semgrep 各版本对 taint_source/taint_sink 使用 tuple-like list 或 location
    对象；这里递归寻找带 path/start 的 location，避免绑定某个小版本 schema。
    """
    repo = repo.resolve()
    trace = extra.get("dataflow_trace")
    if not isinstance(trace, dict):
        return []

    def locations(value, label: str):
        found: list[dict] = []
        if isinstance(value, list):
            for item in value:
                found.extend(locations(item, label))
            return found
        if not isinstance(value, dict):
            return found
        loc = value.get("location") if isinstance(value.get("location"), dict) else value
        path = loc.get("path") if isinstance(loc, dict) else None
        start = loc.get("start", {}) if isinstance(loc, dict) else {}
        if path and isinstance(start, dict):
            try:
                raw_path = Path(str(path))
                try:
                    rel = raw_path.resolve().relative_to(repo).as_posix()
                except ValueError:
                    rel = raw_path.as_posix()
                content = value.get("content") or loc.get("content") or label
                if isinstance(content, dict):
                    content = content.get("value") or content.get("text") or label
                found.append({
                    "file": rel,
                    "line": int(start.get("line", 0)),
                    "message": str(content).strip()[:300] or label,
                })
                return found
            except (TypeError, ValueError):
                pass
        for child in value.values():
            found.extend(locations(child, label))
        return found

    ordered: list[dict] = []
    ordered.extend(locations(trace.get("taint_source"), "taint source"))
    ordered.extend(locations(trace.get("intermediate_vars", []), "intermediate value"))
    ordered.extend(locations(trace.get("taint_sink"), "taint sink"))
    deduped: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    for node in ordered:
        key = (node["file"], node["line"], node["message"])
        if key not in seen:
            seen.add(key)
            deduped.append(node)
    return deduped


def _read_snippet_from_file(repo: Path, rel_path: str, start_line: int, end_line: int) -> str:
    """从源文件读取代码片段（当 semgrep 免费版返回 'requires login' 时使用）。"""
    try:
        file_path = repo / rel_path
        if not file_path.exists():
            return ""

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        # 读取指定行范围（line 从 1 开始）
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), end_line)

        snippet_lines = lines[start_idx:end_idx]
        return ''.join(snippet_lines).strip()
    except Exception:
        return ""


def _infer_rule_id(check_id: str) -> str:
    """从 semgrep check_id 推断我们的规范 rule_id（如 scan-android-r-sg-001-... → R-SG-001）。"""
    import re
    m = re.search(r"r-(sg|dk|lt|jn|ai)-(\d+)", check_id, re.IGNORECASE)
    if m:
        prefix = m.group(1).upper()
        num = m.group(2)
        return f"R-{prefix}-{num:0>3}"
    return check_id
