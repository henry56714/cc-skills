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

模式: 只有 strict（v3 决定，无降级）。任何必需引擎未就绪即 ready=false、中断扫描。

status 值语义:
    ok      — 已就绪，无需操作
    fixed   — 本次运行自动安装/修复后就绪
    missing — 软依赖缺失（仅 git；不影响 strict 就绪判定，仅警告）
    failed  — 必需项未就绪，阻塞扫描（strict 下必中断）
    skip    — 不需要此引擎（在 excluded_engines 中关闭，或依赖它的引擎都关了），跳过

引擎预检范围规则（excluded_engines 中的引擎 → 工具 skip，不参与中断判定）:
    • venv / semgrep / detekt / pmd — 默认必需 + 自动安装（装不上即阻塞）
    • lint                       — 默认必需；依赖 gradlew，缺失即阻塞（gradlew 属工程无法自动安装）
    • repomap                    — tree-sitter 精确层（唯一精确层）：独立 venv 装 tree-sitter，
                                    自动安装但**非阻塞**——缺失则 hunter 地图降级、导航回退纯标准库 source-nav
    • gradle_wrapper             — Lint 启用即必需（需 `./gradlew`）；缺失即阻塞
    • java                       — 仅检测；Detekt/Lint 依赖它，缺失即阻塞（需手动装 JDK）
    • git                        — 仅检测，软依赖（仅影响 --diff，不阻塞）
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
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
        return json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _env_opt_in_engines() -> list[str]:
    env_map = {
        "SCAN_ANDROID_ENABLE_MOBSF": "mobsf",
        "SCAN_ANDROID_ENABLE_FLOWDROID": "flowdroid",
    }
    return [name for var, name in env_map.items() if os.environ.get(var)]


# ──────────────────────────────────────────────────────────────────────────────
# 纯检测函数（无副作用，只读文件系统）
# ──────────────────────────────────────────────────────────────────────────────

def _detect_python() -> CheckResult:
    vi = sys.version_info
    if vi < (3, 8):
        return CheckResult(
            "python3", "failed",
            f"需要 Python 3.8+，当前 {vi.major}.{vi.minor}.{vi.micro}",
            is_hard_required=True,
        )
    return CheckResult("python3", "ok", f"{vi.major}.{vi.minor}.{vi.micro}")


def _detect_java(java_needed: bool) -> CheckResult:
    if not java_needed:
        return CheckResult("java", "skip", "依赖 Java 的引擎均已在配置中关闭")
    ok, detail = check_java()
    if ok:
        return CheckResult("java", "ok", detail)
    # strict：Detekt / Lint 依赖 Java，Java 缺失即阻塞（Java 不自动安装，需手动）
    return CheckResult(
        "java", "missing",
        detail + "  → Detekt / Lint 依赖 Java；strict 模式无法继续，请安装 JDK 17+。",
        is_hard_required=True,
    )


def _detect_venv(venv_needed: bool) -> CheckResult:
    if not venv_needed:
        return CheckResult("venv", "skip", "semgrep 已在配置中关闭，无需 venv")
    if Path(_venv_python()).exists():
        return CheckResult("venv", "ok", str(VENV_DIR))
    # venv 创建是 semgrep 的前提，安装失败构成阻塞
    return CheckResult(
        "venv", "missing", f"尚未创建: {VENV_DIR}",
        can_auto_install=True, is_hard_required=True,
    )


def _detect_semgrep(semgrep_needed: bool) -> CheckResult:
    if not semgrep_needed:
        return CheckResult("semgrep", "skip", "已在 excluded_engines 中关闭")
    venv_sg = venv_bin("semgrep")
    if Path(venv_sg).exists():
        return CheckResult("semgrep", "ok", venv_sg)
    sys_sg = shutil.which("semgrep")
    if sys_sg:
        return CheckResult("semgrep", "ok", f"{sys_sg} (系统路径)")
    return CheckResult(
        "semgrep", "missing", "未安装",
        can_auto_install=True, is_hard_required=True,
    )


def _detect_detekt(detekt_needed: bool) -> CheckResult:
    if not detekt_needed:
        return CheckResult("detekt", "skip", "已在 excluded_engines 中关闭")
    jar = TOOLS_DIR / "detekt" / f"detekt-cli-{_DETEKT_VERSION}-all.jar"
    if jar.exists():
        return CheckResult("detekt", "ok", str(jar))
    # Java 缺失时由 _detect_java 阻塞；此处仍标为必需，安装失败即阻塞
    return CheckResult(
        "detekt", "missing", "JAR 未下载 (~64 MB)",
        can_auto_install=True, is_hard_required=True,
    )


def _detect_pmd(pmd_needed: bool) -> CheckResult:
    if not pmd_needed:
        return CheckResult("pmd", "skip", "已在 excluded_engines 中关闭")
    if find_pmd():
        return CheckResult("pmd", "ok", find_pmd())  # type: ignore[arg-type]
    return CheckResult(
        "pmd", "missing", "未安装 (~40 MB)",
        can_auto_install=True, is_hard_required=True,
    )


def _detect_repomap_venv(repo_root: Path) -> CheckResult:
    """tree-sitter 精确层（唯一精确层，nav_backend=auto/treesitter 时启用）。

    tree-sitter + tree-sitter-language-pack 装在独立 venv（~/.scan-android/repomap-venv/，
    比照 semgrep 隔离）。用于 hunter 的 RepoMap（签名骨架 + PageRank + 跨文件关系）与 verifier
    的 AST 精确导航。**永不阻塞**——venv/包缺失则地图降级、导航自动回退 source-nav（纯标准库）。"""
    pref = (os.environ.get("SCAN_ANDROID_NAV_BACKEND") or "").strip().lower()
    if not pref:
        pref = str(_read_scan_config(repo_root).get("nav_backend", "")).strip().lower()
    if pref == "source":
        return CheckResult("repomap", "skip", "nav_backend=source（纯标准库，无需 tree-sitter）")
    venv_py = REPOMAP_VENV_DIR / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if venv_py.exists():
        # 校验包可导入
        try:
            r = subprocess.run([str(venv_py), "-c", "import tree_sitter, tree_sitter_language_pack"],
                               capture_output=True, timeout=30)
            if r.returncode == 0:
                return CheckResult("repomap", "ok", f"{REPOMAP_VENV_DIR}（tree-sitter 精确层）")
        except Exception:
            pass
    return CheckResult(
        "repomap", "missing",
        f"尚未就绪: {REPOMAP_VENV_DIR}（tree-sitter 精确层；非阻塞，缺失则地图降级、导航回退 source-nav）",
        can_auto_install=True, is_hard_required=False,
    )


def _detect_gradle_wrapper(gradle_needed: bool, repo_root: Path) -> CheckResult:
    """gradlew：Lint 依赖它。"""
    if not gradle_needed:
        return CheckResult("gradle_wrapper", "skip", "lint 已关闭，无需 gradlew")
    gradlew = repo_root / "gradlew"
    if gradlew.exists():
        return CheckResult("gradle_wrapper", "ok", str(gradlew))
    # strict：Lint 依赖 gradlew，缺失即阻塞（gradlew 属工程，无法自动安装）
    return CheckResult(
        "gradle_wrapper", "missing",
        "gradlew 不存在 — Lint 无法运行（strict 中断）。若该工程无 Gradle wrapper，"
        '请在 .scan/config.json 的 excluded_engines 加入 "lint" 关闭它。',
        is_hard_required=True,
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
    config = _read_scan_config(repo_root)
    excluded_engines: list[str] = config.get("excluded_engines", [])

    # 每个引擎是否需要（决定其工具是否计入 strict 中断判定）。
    # excluded_engines 里的引擎 → 工具标记 skip，不参与就绪判定（决定 3）。
    semgrep_needed = "semgrep" not in excluded_engines
    detekt_needed = "detekt" not in excluded_engines
    pmd_needed = "pmd" not in excluded_engines
    lint_needed = "lint" not in excluded_engines
    # 依赖关系：Detekt / PMD / Lint 需要 Java；Semgrep 需要 venv。
    java_needed = detekt_needed or pmd_needed or lint_needed
    venv_needed = semgrep_needed
    # gradlew：Lint 依赖它。
    gradle_needed = lint_needed

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

    # ── 后处理（strict）：标记 fixed / 任何 hard-required 仍缺失即升级为 blocker ──
    # v3 决定：只有 strict 模式，绝不降级。必需引擎未就绪即中断，无论是否尝试过安装、
    # 能否自动安装（如 Java 不自动装均构成阻塞）。repomap 精确层非必需，缺失不阻塞（回退 source-nav）。
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
        lines.append("❌ 以下必需项未就绪，strict 模式中止扫描（不降级）：")
        for b in result["blockers"]:
            lines.append(f"   • {b}")
        lines.append("")
        lines.append("请按提示修复后重试。扫描已中止。")
    else:
        lines.append("")
        lines.append("✅ 预检通过，所有必需引擎就绪，开始扫描…")

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
