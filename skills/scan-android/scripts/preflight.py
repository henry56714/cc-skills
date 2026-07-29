#!/usr/bin/env python3
"""
scan-android 预检工具

在扫描开始前检查所有必需的引擎与环境条件，自动下载/修复可自动处理的问题，
循环"检测 → 安装 → 再检测"直到 ready=true 或出现无法自动修复的阻塞项。

用法:
    python3 preflight.py [--repo-root DIR]

--repo-root DIR 被扫描的仓库根目录（默认 .）

退出码:
    0 — 所有必需检查通过（或已自动修复），可继续扫描
    1 — 存在无法自动修复的阻塞问题，已输出说明

stdout JSON:
    {
      "ready": true,
      "checks": [
        {"name": "python3",        "status": "ok",      "detail": "3.12.1"},
        {"name": "java",           "status": "ok",      "detail": "openjdk 17"},
        {"name": "venv",           "status": "fixed",   "detail": "/path/to/venv"},
        {"name": "semgrep",        "status": "fixed",   "detail": "/path/to/semgrep"},
        {"name": "detekt",         "status": "fixed",   "detail": "/path/to/detekt.jar"},
        {"name": "repomap",        "status": "fixed",   "detail": "/path/to/repomap-venv"},
        {"name": "gradle_wrapper", "status": "ok",      "detail": "./gradlew"},
        {"name": "git",            "status": "ok",      "detail": "git 2.39.3"}
      ],
      "blockers": [],
      "warnings": []
    }

模式: Python 运行时是唯一硬前提。扫描引擎缺失会自动安装；仍不可用时记录为 warning，
后续保留其他引擎的部分结果并把整次扫描标记为 incomplete。

status 值语义:
    ok      — 已就绪，无需操作
    fixed   — 本次运行自动安装/修复后就绪
    missing — 软依赖缺失；后续扫描会标记 incomplete
    failed  — Python 等硬前提未就绪，阻塞扫描
    skip    — 不需要此引擎（在 excluded_engines 中关闭，或依赖它的引擎都关了），跳过

引擎预检范围规则（excluded_engines 中的引擎 → 工具 skip，不参与中断判定）:
    • venv / semgrep / detekt / pmd — 自动安装；失败为 warning
    • lint                       — 仅在明确允许 Gradle 执行时启用
    • repomap                    — tree-sitter 语法索引；失败回退 source-nav
    • gradle_wrapper             — 仅在 Lint 已授权时检查
    • java                       — Detekt/PMD/Lint 依赖；缺失为 warning
    • git                        — 仅检测，软依赖（仅影响 --diff，不阻塞）
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# 路径定位
# ──────────────────────────────────────────────────────────────────────────────
_SCRIPTS_DIR = Path(__file__).resolve().parent
_SKILL_ROOT = _SCRIPTS_DIR.parent

sys.path.insert(0, str(_SCRIPTS_DIR))
from tools.installer import (  # noqa: E402  (依赖上方 sys.path.insert)
    TOOLS_DIR,
    VENV_DIR,
    _DETEKT_VERSION,
    _PMD_VERSION,
    _SEMGREP_VERSION,
    _TREE_SITTER_LANGUAGE_PACK_VERSION,
    _TREE_SITTER_VERSION,
    _python_version_ok,
    _venv_package_version,
    _venv_python,
    venv_bin,
    check_java,
    ensure_venv,
    ensure_semgrep,
    ensure_detekt,
    ensure_pmd,
    find_pmd,
    ensure_repomap_venv,
    REPOMAP_VENV_DIR,
)


# ──────────────────────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────────────────────

class CheckResult:
    """
    单项检查结果。

    Attributes:
        name            检查项名称
        status          ok | fixed | missing | failed | skip
        detail          人类可读说明（路径 / 错误原因 / 提示）
        can_auto_install 当前状态下是否可以触发自动安装（动态决定）
        is_hard_required 安装失败是否构成阻塞（hard=True → blocker）
    """
    def __init__(
        self,
        name: str,
        status: str,
        detail: str = "",
        can_auto_install: bool = False,
        is_hard_required: bool = False,
    ):
        self.name = name
        self.status = status
        self.detail = detail
        self.can_auto_install = can_auto_install
        self.is_hard_required = is_hard_required

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail}

    @property
    def is_ready(self) -> bool:
        return self.status in ("ok", "fixed", "skip")

    @property
    def is_blocker(self) -> bool:
        return self.status == "failed"


# ──────────────────────────────────────────────────────────────────────────────
# 读取项目配置
# ──────────────────────────────────────────────────────────────────────────────

def _read_scan_config(repo_root: Path) -> dict:
    config_path = repo_root / ".scan" / "config.json"
    if not config_path.exists():
        return {}
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"__config_error__": "top-level JSON must be an object"}
        return data
    except Exception as exc:
        return {"__config_error__": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# 纯检测函数（无副作用，只读文件系统）
# ──────────────────────────────────────────────────────────────────────────────

def _detect_python() -> CheckResult:
    vi = sys.version_info
    if vi < (3, 9):
        return CheckResult(
            "python3", "failed",
            f"编排脚本需要 Python 3.9+，当前 {vi.major}.{vi.minor}.{vi.micro}",
            is_hard_required=True,
        )
    return CheckResult("python3", "ok", f"{vi.major}.{vi.minor}.{vi.micro}")


def _detect_java(java_needed: bool) -> CheckResult:
    if not java_needed:
        return CheckResult("java", "skip", "依赖 Java 的引擎均已在配置中关闭")
    ok, detail = check_java()
    if ok:
        return CheckResult("java", "ok", detail)
    return CheckResult(
        "java", "missing",
        detail + "  → Detekt / PMD / Lint 将不可用；其他引擎仍会运行。",
        is_hard_required=False,
    )


def _detect_venv(venv_needed: bool) -> CheckResult:
    if not venv_needed:
        return CheckResult("venv", "skip", "semgrep 已在配置中关闭，无需 venv")
    if Path(_venv_python()).exists() and _python_version_ok(_venv_python(), (3, 10)):
        return CheckResult("venv", "ok", str(VENV_DIR))
    return CheckResult(
        "venv", "missing", f"尚未创建或 Python 低于 3.10: {VENV_DIR}",
        can_auto_install=True, is_hard_required=False,
    )


def _detect_semgrep(semgrep_needed: bool) -> CheckResult:
    if not semgrep_needed:
        return CheckResult("semgrep", "skip", "已在 excluded_engines 中关闭")
    venv_sg = venv_bin("semgrep")
    installed = _venv_package_version("semgrep")
    if Path(venv_sg).exists() and installed == _SEMGREP_VERSION:
        return CheckResult("semgrep", "ok", f"{venv_sg} ({installed})")
    detail = "未安装"
    if installed:
        detail = f"版本不匹配: {installed}，需要 {_SEMGREP_VERSION}"
    return CheckResult(
        "semgrep", "missing", detail,
        can_auto_install=True, is_hard_required=False,
    )


def _detect_detekt(detekt_needed: bool) -> CheckResult:
    if not detekt_needed:
        return CheckResult("detekt", "skip", "已在 excluded_engines 中关闭")
    jar = TOOLS_DIR / "detekt" / f"detekt-cli-{_DETEKT_VERSION}-all.jar"
    if jar.exists() and zipfile.is_zipfile(jar):
        return CheckResult("detekt", "ok", str(jar))
    # Java 缺失时由 _detect_java 阻塞；此处仍标为必需，安装失败即阻塞
    return CheckResult(
        "detekt", "missing", "JAR 未下载 (~64 MB)",
        can_auto_install=True, is_hard_required=False,
    )


def _detect_pmd(pmd_needed: bool) -> CheckResult:
    if not pmd_needed:
        return CheckResult("pmd", "skip", "已在 excluded_engines 中关闭")
    pmd = find_pmd()
    if pmd:
        return CheckResult("pmd", "ok", f"{pmd} ({_PMD_VERSION})")
    return CheckResult(
        "pmd", "missing", "未安装 (~40 MB)",
        can_auto_install=True, is_hard_required=False,
    )


def _detect_repomap_venv(repo_root: Path) -> CheckResult:
    """tree-sitter 语法索引层（nav_backend=auto/treesitter 时启用）。

    tree-sitter + tree-sitter-language-pack 装在独立 venv（~/.scan-android/repomap-venv/，
    比照 semgrep 隔离）。用于 hunter 的 RepoMap（签名骨架 + PageRank + 跨文件关系）与 verifier
    的语法级导航。**永不阻塞**——venv/包缺失则地图降级、导航自动回退 source-nav（纯标准库）。"""
    pref = (os.environ.get("SCAN_ANDROID_NAV_BACKEND") or "").strip().lower()
    if not pref:
        pref = str(_read_scan_config(repo_root).get("nav_backend", "")).strip().lower()
    if pref == "source":
        return CheckResult("repomap", "skip", "nav_backend=source（纯标准库，无需 tree-sitter）")
    venv_py = REPOMAP_VENV_DIR / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if venv_py.exists():
        # 校验包可导入
        try:
            version_check = (
                "import importlib.metadata as m, tree_sitter, tree_sitter_language_pack; "
                f"assert m.version('tree-sitter') == {_TREE_SITTER_VERSION!r}; "
                "assert m.version('tree-sitter-language-pack') == "
                f"{_TREE_SITTER_LANGUAGE_PACK_VERSION!r}"
            )
            r = subprocess.run([str(venv_py), "-c", version_check],
                               capture_output=True, timeout=30)
            if r.returncode == 0:
                return CheckResult("repomap", "ok", f"{REPOMAP_VENV_DIR}（tree-sitter 语法索引）")
        except Exception:
            pass
    return CheckResult(
        "repomap", "missing",
        f"尚未就绪: {REPOMAP_VENV_DIR}（tree-sitter 语法索引；非阻塞，缺失则地图降级、导航回退 source-nav）",
        can_auto_install=True, is_hard_required=False,
    )


def _detect_gradle_wrapper(gradle_needed: bool, repo_root: Path) -> CheckResult:
    """gradlew：Lint 依赖它。"""
    if not gradle_needed:
        return CheckResult("gradle_wrapper", "skip", "未授权执行 Gradle/Lint，无需 gradlew")
    gradlew = repo_root / "gradlew"
    if gradlew.exists():
        return CheckResult("gradle_wrapper", "ok", str(gradlew))
    return CheckResult(
        "gradle_wrapper", "missing",
        "gradlew 不存在 — Lint 无法运行，扫描将标记 incomplete。若该工程无 Gradle wrapper，"
        '请在 .scan/config.json 的 excluded_engines 加入 "lint" 关闭它。',
        is_hard_required=False,
    )


def _detect_git() -> CheckResult:
    git = shutil.which("git")
    if not git:
        return CheckResult(
            "git", "missing",
            "git 不可用 — --diff 模式不可用，请改用 --module 或 --full",
        )
    try:
        ver = subprocess.check_output(["git", "--version"], text=True, timeout=5).strip()
        return CheckResult("git", "ok", ver)
    except Exception:
        return CheckResult("git", "ok", git)


def _detect_all(
    repo_root: Path,
    *,
    java_needed: bool,
    venv_needed: bool,
    semgrep_needed: bool,
    detekt_needed: bool,
    pmd_needed: bool,
    gradle_needed: bool,
) -> list[CheckResult]:
    results: list[CheckResult] = [
        _detect_python(),
        _detect_java(java_needed),
        _detect_venv(venv_needed),
        _detect_semgrep(semgrep_needed),
        _detect_detekt(detekt_needed),
        _detect_pmd(pmd_needed),
        _detect_repomap_venv(repo_root),
        _detect_gradle_wrapper(gradle_needed, repo_root),
        _detect_git(),
    ]
    return results


# ──────────────────────────────────────────────────────────────────────────────
# 安装函数（有副作用）
# ──────────────────────────────────────────────────────────────────────────────

def _try_install(name: str) -> tuple[bool, str]:
    """尝试安装指定引擎/依赖。返回 (success, detail)。"""
    try:
        if name == "venv":
            path = ensure_venv()
            return True, str(path)
        elif name == "semgrep":
            # semgrep 依赖 venv，先确保 venv 存在
            if not Path(_venv_python()).exists():
                ensure_venv()
            path, _ = ensure_semgrep()
            return True, path
        elif name == "detekt":
            path, _ = ensure_detekt()
            return True, path
        elif name == "pmd":
            path, _ = ensure_pmd()
            return True, path
        elif name == "repomap":
            path = ensure_repomap_venv()
            return True, str(path)
        else:
            return False, f"不支持自动安装: {name}"
    except Exception as e:
        return False, str(e)


# ──────────────────────────────────────────────────────────────────────────────
# 主流程：检测 → 安装 → 再检测，循环直到 ready 或无可安装项
# ──────────────────────────────────────────────────────────────────────────────

def run_preflight(repo_root: Path) -> dict:
    config = dict(_read_scan_config(repo_root))
    config_error = str(config.pop("__config_error__", ""))
    raw_excluded = config.get("excluded_engines", [])
    excluded_engines: list[str] = (
        [str(x) for x in raw_excluded] if isinstance(raw_excluded, list) else []
    )

    # 每个引擎是否需要（被配置排除的引擎不检测）。
    # excluded_engines 里的引擎 → 工具标记 skip，不参与就绪判定（决定 3）。
    semgrep_needed = "semgrep" not in excluded_engines
    detekt_needed = "detekt" not in excluded_engines
    pmd_needed = "pmd" not in excluded_engines
    lint_needed = "lint" not in excluded_engines
    allow_gradle_execution = config.get("allow_gradle_execution", False) is True
    # 依赖关系：Detekt / PMD / Lint 需要 Java；Semgrep 需要 venv。
    java_needed = detekt_needed or pmd_needed or (lint_needed and allow_gradle_execution)
    venv_needed = semgrep_needed
    # gradlew：Lint 依赖它。
    gradle_needed = lint_needed and allow_gradle_execution

    detect_kwargs = dict(
        java_needed=java_needed,
        venv_needed=venv_needed,
        semgrep_needed=semgrep_needed,
        detekt_needed=detekt_needed,
        pmd_needed=pmd_needed,
        gradle_needed=gradle_needed,
    )

    # 跟踪已尝试安装的引擎，防止无限重试
    attempted_installs: set[str] = set()
    # 跟踪哪些引擎是通过本次预检安装的
    newly_installed: set[str] = set()

    results: list[CheckResult] = []

    while True:
        results = _detect_all(repo_root, **detect_kwargs)

        # 找出：missing + 可自动安装 + 还未尝试过安装
        to_install = [
            r for r in results
            if r.status == "missing"
            and r.can_auto_install
            and r.name not in attempted_installs
        ]

        if not to_install:
            break  # 没有新的可安装项，退出循环

        _eprint(f"\n[preflight] 发现 {len(to_install)} 项缺失，开始自动安装：")
        for r in to_install:
            _eprint(f"  ⏳ 安装 {r.name}...")
            success, detail = _try_install(r.name)
            attempted_installs.add(r.name)
            if success:
                newly_installed.add(r.name)
                _eprint(f"  ✅ {r.name} 安装成功: {detail}")
            else:
                _eprint(f"  ❌ {r.name} 安装失败: {detail}")
        # 继续循环，重新检测

    # 标记 fixed；只有 Python 运行时等真正硬前提才升级为 blocker。
    for r in results:
        if r.name in newly_installed and r.status == "ok":
            r.status = "fixed"
        elif r.status == "missing" and r.is_hard_required:
            r.status = "failed"
            if r.name in attempted_installs:
                r.detail = f"安装失败（请检查网络）: {r.detail}"
            else:
                r.detail = f"必需但无法自动安装，请手动安装后重试: {r.detail}"

    # ── 汇总 ──
    blockers = [r.detail for r in results if r.is_blocker]
    warnings = [f"{r.name}: {r.detail}" for r in results if r.status == "missing"]
    if config_error:
        warnings.insert(0, f"config: 配置无效，已使用安全默认值: {config_error}")

    return {
        "ready": len(blockers) == 0,
        "checks": [r.to_dict() for r in results],
        "blockers": blockers,
        "warnings": warnings,
    }


# ──────────────────────────────────────────────────────────────────────────────
# 人类可读输出（stderr）
# ──────────────────────────────────────────────────────────────────────────────

_STATUS_ICON = {
    "ok":      "✅",
    "fixed":   "🔧",
    "missing": "⚠️ ",
    "failed":  "❌",
    "skip":    "⏭️ ",
}


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _print_summary(result: dict) -> None:
    lines = ["", "┌─ scan-android 预检结果 " + "─" * 38]
    for c in result["checks"]:
        icon = _STATUS_ICON.get(c["status"], "? ")
        detail = c["detail"]
        if len(detail) > 70:
            detail = detail[:67] + "…"
        lines.append(f"│  {icon}  {c['name']:<20} {detail}")
    lines.append("└" + "─" * 62)

    if result["blockers"]:
        lines.append("")
        lines.append("❌ 以下运行时硬前提未就绪，扫描中止：")
        for b in result["blockers"]:
            lines.append(f"   • {b}")
        lines.append("")
        lines.append("请按提示修复后重试。扫描已中止。")
    else:
        lines.append("")
        lines.append("✅ 预检通过；缺失的可选引擎会使报告明确标记 incomplete。")

    lines.append("")
    _eprint("\n".join(lines))


# ──────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ──────────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--repo-root", default=".",
        help="被扫描的仓库根目录（默认 .）",
    )
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()

    result = run_preflight(repo_root)

    _print_summary(result)

    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")

    return 0 if result["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
