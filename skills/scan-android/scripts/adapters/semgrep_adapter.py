"""Semgrep adapter —— P1 广度扫描引擎（AST 感知，比纯正则精确）。

自动探测 semgrep 是否可用；未安装则通过 pip 自动安装。
规则来源（v3）：
- **社区 registry 规则包**（广度主力，数千条）：按 check 类别挂 `p/...` 包；
- **本地自写规则** `queries/semgrep/`：只补社区库未覆盖的 Android/项目特定缺口。
两者结果统一归一化为 Candidate 契约。registry 默认开启，离线场景可在
`.scan/config.json` 用 `semgrep_use_registry:false` 关闭。
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
    - use_registry: 默认 True；离线场景可设 false。
    - packs_override: 显式覆盖默认 registry 包清单；None = 用默认全集。
    """
    cfg: dict = {}
    p = repo / ".scan" / "config.json"
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            pass
    use_registry = bool(cfg.get("semgrep_use_registry", True))
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

        # 社区 registry 规则包（v3 广度主力）。默认开，离线可在配置关闭。
        use_registry, packs_override = _load_semgrep_config(ctx.repo)
        registry_packs = (packs_override if packs_override is not None else _DEFAULT_REGISTRY_PACKS) if use_registry else []

        if not rule_files and not registry_packs:
            result.notes.append({"engine": self.name, "note": "没有匹配的 semgrep 规则（本地 + registry 均为空）"})
            return result

        # 构建 semgrep 命令：本地规则 + 社区 registry 包
        cmd = [semgrep, "--json", "--quiet", "--no-git-ignore"]
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

        # 传入仓库根，让 semgrep 扫描整个仓库（后续按 scope 过滤）
        cmd.append(str(ctx.repo))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(ctx.repo),
            )
        except subprocess.TimeoutExpired:
            result.notes.append({"engine": self.name, "note": "semgrep 超时（300s），结果可能不完整"})
            return result
        except Exception as e:
            result.available = False
            result.unavailable_reason = f"semgrep 运行失败: {e}"
            return result

        # semgrep --json 的退出码：0=无发现，1=有发现，2=错误
        if proc.returncode not in (0, 1):
            result.notes.append({
                "engine": self.name,
                "note": f"semgrep 退出码 {proc.returncode}，stderr: {proc.stderr[:500]}",
            })
            if not proc.stdout.strip():
                result.available = False
                result.unavailable_reason = "semgrep 返回空结果（可能出错）"
                return result

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            result.notes.append({"engine": self.name, "note": f"semgrep JSON 解析失败: {e}"})
            return result

        # 解析结果
        scope_set = set(ctx.scope_files)
        rule_hit_count: dict[str, int] = {}

        for item in data.get("results", []):
            try:
                candidate = _parse_result(item, ctx.repo, scope_set)
            except Exception:
                continue
            if candidate is None:
                continue
            rule_id = candidate.rule_id
            rule_hit_count[rule_id] = rule_hit_count.get(rule_id, 0) + 1
            if rule_hit_count[rule_id] > ctx.max_per_rule:
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
            result.notes.append({"engine": self.name, "note": f"semgrep error: {err.get('message', '')}"})

        return result


def _find_semgrep() -> str | None:
    # 1. 优先用 scan-android venv（版本固定、不受系统/conda 影响）
    try:
        from tools.installer import venv_bin
        venv_semgrep = venv_bin("semgrep")
        if Path(venv_semgrep).exists():
            return venv_semgrep
    except Exception:
        pass
    # 2. 系统 PATH 已有安装（兼容用户自行安装或 conda 环境中的 semgrep）
    import shutil
    return shutil.which("semgrep")


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

    snippet = extra.get("lines", "").strip()[:300]

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
    )


def _infer_rule_id(check_id: str) -> str:
    """从 semgrep check_id 推断我们的规范 rule_id（如 scan-android-r-sec-001-... → R-SEC-001）。"""
    import re
    m = re.search(r"r-(sec|stb|prf)-(\d+)", check_id, re.IGNORECASE)
    if m:
        prefix = m.group(1).upper()
        num = m.group(2)
        return f"R-{prefix}-{num:0>3}"
    return check_id
