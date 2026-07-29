"""
scan-android v2 引擎自动检测与安装。

每个 ensure_*() 函数:
  1. 检查工具是否已安装（venv / PATH / 本地缓存）
  2. 未安装则自动下载/安装
  3. 返回 (tool_path: str, was_just_installed: bool)

目录布局:
  ~/.scan-android/
    venv/           Python 虚拟环境（semgrep 等 pip 包，隔离于系统/conda）
    repomap-venv/   tree-sitter 语法索引 venv（tree-sitter + tree-sitter-language-pack，隔离）
    tools/          JVM 工具二进制（Detekt / PMD）

可通过环境变量覆盖路径:
  SCAN_ANDROID_VENV_DIR   虚拟环境根（默认 ~/.scan-android/venv）
  SCAN_ANDROID_TOOLS_DIR  JVM 工具根（默认 ~/.scan-android/tools）
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------

TOOLS_DIR = Path(os.environ.get(
    "SCAN_ANDROID_TOOLS_DIR",
    Path.home() / ".scan-android" / "tools",
))

VENV_DIR = Path(os.environ.get(
    "SCAN_ANDROID_VENV_DIR",
    Path.home() / ".scan-android" / "venv",
))

# tree-sitter 语法索引专属 venv（与 semgrep venv 隔离，避免依赖冲突）
REPOMAP_VENV_DIR = Path(os.environ.get(
    "SCAN_ANDROID_REPOMAP_VENV",
    Path.home() / ".scan-android" / "repomap-venv",
))

# skill 根目录（requirements.txt 所在位置）
_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent

# 固定版本（定期更新以获取安全补丁）
_DETEKT_VERSION = "1.23.7"
_PMD_VERSION = "7.10.0"
_SEMGREP_VERSION = "1.165.0"
_TREE_SITTER_VERSION = "0.26.0"
_TREE_SITTER_LANGUAGE_PACK_VERSION = "1.13.3"


# ---------------------------------------------------------------------------
# Python 虚拟环境管理
# ---------------------------------------------------------------------------


def ensure_venv() -> Path:
    """确保 scan-android 专属 venv 存在并返回其根路径。

    使用 Python 标准库 venv 模块创建，与系统 Python / conda / pyenv 完全隔离。
    venv 只用于 pip 包（目前仅 semgrep）；JVM 工具走 tools/ 目录。
    """
    python_bin = _venv_python()
    if Path(python_bin).exists() and _python_version_ok(python_bin, (3, 10)):
        return VENV_DIR
    _print(f"[installer] 创建虚拟环境: {VENV_DIR}")
    bootstrap = _find_python((3, 10))
    if not bootstrap:
        raise RuntimeError("Semgrep 需要 Python 3.10+；未找到可用于创建隔离 venv 的解释器")
    VENV_DIR.parent.mkdir(parents=True, exist_ok=True)
    subprocess.check_call(
        [bootstrap, "-m", "venv", "--clear", str(VENV_DIR)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    # 升级 pip 本身
    subprocess.check_call(
        [python_bin, "-m", "pip", "install", "--upgrade", "pip",
         "--quiet", "--disable-pip-version-check"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return VENV_DIR


def ensure_python_deps() -> bool:
    """安装 requirements.txt 中所有 Python 依赖到 venv。返回是否执行了安装。"""
    req_file = _SKILL_ROOT / "requirements.txt"
    if not req_file.exists():
        return False
    ensure_venv()
    python = _venv_python()
    _print(f"[installer] 安装 Python 依赖（{req_file.name}）到 venv...")
    subprocess.check_call(
        [python, "-m", "pip", "install", "-r", str(req_file),
         "--quiet", "--disable-pip-version-check"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    return True


def venv_bin(name: str) -> str:
    """返回 venv 中某个可执行文件的绝对路径。"""
    if platform.system() == "Windows":
        return str(VENV_DIR / "Scripts" / f"{name}.exe")
    return str(VENV_DIR / "bin" / name)


def _venv_python() -> str:
    if platform.system() == "Windows":
        return str(VENV_DIR / "Scripts" / "python.exe")
    return str(VENV_DIR / "bin" / "python")


def _python_version_ok(executable: str, minimum: tuple[int, int]) -> bool:
    try:
        proc = subprocess.run(
            [executable, "-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"],
            capture_output=True, text=True, timeout=10,
        )
        major, minor = (int(x) for x in proc.stdout.strip().split(".", 1))
        return proc.returncode == 0 and (major, minor) >= minimum
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def _find_python(minimum: tuple[int, int]) -> str | None:
    candidates = [sys.executable]
    candidates.extend(
        p for name in ("python3.13", "python3.12", "python3.11", "python3.10", "python3")
        for p in [shutil.which(name)] if p
    )
    for executable in dict.fromkeys(candidates):
        if executable and _python_version_ok(executable, minimum):
            return executable
    return None


# ---------------------------------------------------------------------------
# pip 包
# ---------------------------------------------------------------------------


def ensure_semgrep() -> tuple[str, bool]:
    """确保 semgrep 在 venv 中可用，返回 (executable_path, was_just_installed)。

    只使用 skill 管理且版本固定的 venv，避免 PATH 中同名工具造成结果漂移。
    首次安装时通过 pip 写入 venv，不污染系统环境。
    """
    venv_semgrep = venv_bin("semgrep")
    if Path(venv_semgrep).exists() and _venv_package_version("semgrep") == _SEMGREP_VERSION:
        return venv_semgrep, False
    _install_semgrep_to_venv()
    path = venv_bin("semgrep")
    return path, True


def _install_semgrep_to_venv() -> None:
    ensure_venv()
    _print("[installer] 在虚拟环境中安装 semgrep（pip）...")
    subprocess.check_call(
        [_venv_python(), "-m", "pip", "install", f"semgrep=={_SEMGREP_VERSION}",
         "--quiet", "--disable-pip-version-check"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if (
        not Path(venv_bin("semgrep")).exists()
        or _venv_package_version("semgrep") != _SEMGREP_VERSION
    ):
        raise RuntimeError(f"Semgrep 安装后版本校验失败（需要 {_SEMGREP_VERSION}）")


def _venv_package_version(package: str) -> str:
    try:
        proc = subprocess.run(
            [_venv_python(), "-c", f"import importlib.metadata as m; print(m.version({package!r}))"],
            capture_output=True, text=True, timeout=20,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _repomap_venv_python() -> str:
    if platform.system() == "Windows":
        return str(REPOMAP_VENV_DIR / "Scripts" / "python.exe")
    return str(REPOMAP_VENV_DIR / "bin" / "python")


def ensure_repomap_venv() -> Path:
    """确保 tree-sitter 语法索引的独立 venv 就绪（含 tree-sitter + tree-sitter-language-pack）。

    与 semgrep venv 隔离，避免依赖冲突。**调用方须把失败视为非阻塞**——缺失时
    repo_map.py 会降级、nav_tools.py 会回退纯标准库 source-nav。返回 venv 根路径。
    """
    py = _repomap_venv_python()
    if not Path(py).exists() or not _python_version_ok(py, (3, 10)):
        _print(f"[installer] 创建 tree-sitter venv: {REPOMAP_VENV_DIR}")
        bootstrap = _find_python((3, 10))
        if not bootstrap:
            raise RuntimeError("tree-sitter 隔离环境需要 Python 3.10+，但未找到可用解释器")
        REPOMAP_VENV_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call(
            [bootstrap, "-m", "venv", "--clear", str(REPOMAP_VENV_DIR)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        subprocess.check_call(
            [py, "-m", "pip", "install", "--upgrade", "pip",
             "--quiet", "--disable-pip-version-check"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    # 校验/补装包
    version_check = (
        "import importlib.metadata as m, tree_sitter, tree_sitter_language_pack; "
        f"assert m.version('tree-sitter') == {_TREE_SITTER_VERSION!r}; "
        f"assert m.version('tree-sitter-language-pack') == {_TREE_SITTER_LANGUAGE_PACK_VERSION!r}"
    )
    check = subprocess.run([py, "-c", version_check], capture_output=True)
    if check.returncode != 0:
        _print("[installer] 安装 tree-sitter + tree-sitter-language-pack（pip）...")
        subprocess.check_call(
            [py, "-m", "pip", "install",
             f"tree-sitter=={_TREE_SITTER_VERSION}",
             f"tree-sitter-language-pack=={_TREE_SITTER_LANGUAGE_PACK_VERSION}",
             "--quiet", "--disable-pip-version-check"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        check = subprocess.run([py, "-c", version_check], capture_output=True)
        if check.returncode != 0:
            raise RuntimeError("tree-sitter 隔离环境安装后版本校验失败")
    return REPOMAP_VENV_DIR


# ---------------------------------------------------------------------------
# JVM 工具（JAR / 二进制）
# ---------------------------------------------------------------------------


def ensure_detekt() -> tuple[str, bool]:
    jar = TOOLS_DIR / "detekt" / f"detekt-cli-{_DETEKT_VERSION}-all.jar"
    if jar.exists() and zipfile.is_zipfile(jar):
        return str(jar), False
    if jar.exists():
        jar.unlink()
    _print(f"[installer] 下载 Detekt {_DETEKT_VERSION} (~64 MB)...")
    url = (
        f"https://github.com/detekt/detekt/releases/download/v{_DETEKT_VERSION}/"
        f"detekt-cli-{_DETEKT_VERSION}-all.jar"
    )
    jar.parent.mkdir(parents=True, exist_ok=True)
    _download(url, jar)
    if not zipfile.is_zipfile(jar):
        jar.unlink(missing_ok=True)
        raise RuntimeError("Detekt 下载内容不是有效 JAR")
    return str(jar), True


def find_pmd() -> str | None:
    """返回 skill 管理的固定版本 PMD；不接受 PATH 或其他缓存版本。"""
    expected = TOOLS_DIR / "pmd" / f"pmd-bin-{_PMD_VERSION}" / "bin" / "pmd"
    return str(expected) if expected.exists() else None


def ensure_pmd() -> tuple[str, bool]:
    existing = find_pmd()
    if existing:
        binp = Path(existing)
        if binp.exists() and not os.access(binp, os.X_OK):
            binp.chmod(binp.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return existing, False
    version = _PMD_VERSION
    _print(f"[installer] 下载 PMD {version} (~40 MB)...")
    # PMD release tag 形如 pmd_releases/7.10.0（URL 中 / 需转义为 %2F）
    url = (
        f"https://github.com/pmd/pmd/releases/download/"
        f"pmd_releases%2F{version}/pmd-dist-{version}-bin.zip"
    )
    pmd_root = TOOLS_DIR / "pmd"
    dest_zip = pmd_root / f"pmd-dist-{version}-bin.zip"
    dest_zip.parent.mkdir(parents=True, exist_ok=True)
    _download(url, dest_zip)
    _print("[installer] 解压 PMD...")
    with zipfile.ZipFile(dest_zip) as zf:
        _safe_extract_zip(zf, pmd_root)
    dest_zip.unlink(missing_ok=True)
    binp = pmd_root / f"pmd-bin-{version}" / "bin" / "pmd"
    if not binp.exists():
        raise RuntimeError("PMD 解压后未找到 bin/pmd")
    binp.chmod(binp.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(binp), True


def check_java() -> tuple[bool, str]:
    """检查 Java 是否可用（Detekt / PMD / Lint 需要 Java 11+）。"""
    java = shutil.which("java")
    if not java:
        return False, "java 未找到，请安装 Java 11+（brew install openjdk@21）"
    try:
        out = subprocess.check_output(
            ["java", "-version"], stderr=subprocess.STDOUT, text=True, timeout=5,
        )
        return True, out.strip().split("\n")[0]
    except Exception as e:
        return False, str(e)


def _safe_extract_zip(zf: zipfile.ZipFile, destination: Path) -> None:
    """Reject absolute and traversal entries before extracting downloaded tools."""
    root = destination.resolve()
    for member in zf.infolist():
        target = (root / member.filename).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise RuntimeError(f"ZIP 含越界路径，拒绝解压: {member.filename}") from exc
    zf.extractall(root)


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------


def _print(msg: str) -> None:
    print(msg, flush=True, file=sys.stderr)


def _download(url: str, dest: Path, chunk: int = 1024 * 512, max_retries: int = 3) -> None:
    """下载文件到 dest，支持断点续传和自动重试。

    - 每次失败后保留已下载的 .tmp 文件，下次尝试用 Range: bytes=N- 续传。
    - 若服务器不支持 Range（返回 200 而非 206），自动从头重下。
    - 重试间隔：5s → 15s → 45s（指数退避）。
    """
    tmp = Path(str(dest) + ".tmp")
    last_err: Exception | None = None

    for attempt in range(1, max_retries + 1):
        resume_from = tmp.stat().st_size if tmp.exists() else 0

        if resume_from > 0:
            _print(f"[installer] 断点续传（已下载 {resume_from // 1048576} MB，"
                   f"第 {attempt}/{max_retries} 次尝试）...")
        elif attempt > 1:
            _print(f"[installer] 重试下载（第 {attempt}/{max_retries} 次）...")

        try:
            headers = {"User-Agent": "scan-android-installer/2"}
            if resume_from > 0:
                headers["Range"] = f"bytes={resume_from}-"

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=600) as r:
                status = getattr(r, "status", 200)
                # 服务器支持断点续传（206 Partial Content）才追加写；否则从头来
                if resume_from > 0 and status == 206:
                    mode = "ab"
                    downloaded = resume_from
                    content_len = int(r.headers.get("Content-Length", 0))
                    total = resume_from + content_len if content_len else 0
                else:
                    mode = "wb"
                    downloaded = 0
                    resume_from = 0
                    total = int(r.headers.get("Content-Length", 0))

                with open(tmp, mode) as f:
                    while True:
                        data = r.read(chunk)
                        if not data:
                            break
                        f.write(data)
                        downloaded += len(data)
                        if total:
                            pct = downloaded * 100 // total
                            mb_done = downloaded // 1048576
                            mb_total = total // 1048576
                            print(
                                f"\r  {pct:3d}%  {mb_done} MB / {mb_total} MB",
                                end="", flush=True, file=sys.stderr,
                            )

            print(file=sys.stderr)
            tmp.rename(dest)
            return  # 成功

        except Exception as e:
            last_err = e
            if attempt < max_retries:
                delay = 5 * (3 ** (attempt - 1))  # 5s, 15s, 45s
                _print(f"[installer] 下载出错（{e}），{delay}s 后重试...")
                time.sleep(delay)
            else:
                if tmp.exists():
                    tmp.unlink()
                raise RuntimeError(
                    f"下载失败（已重试 {max_retries} 次）: {last_err}"
                ) from last_err


def _fetch_latest_github_version(owner: str, repo: str) -> str | None:
    try:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "scan-android"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
            tag = data.get("tag_name", "")
            return tag.lstrip("v") if tag else None
    except Exception:
        return None


def _find_in_pip_scripts(name: str) -> str | None:
    scripts_dir = Path(sys.executable).parent
    candidate = scripts_dir / name
    if candidate.exists():
        return str(candidate)
    return None


# ---------------------------------------------------------------------------
# CLI（python3 installer.py --install <tool>）
# ---------------------------------------------------------------------------


def _cli_main() -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="scan-android 引擎安装工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
可安装的工具:
  venv        创建 Python 虚拟环境并安装 requirements.txt
  semgrep     semgrep（安装到 venv）
  detekt      Detekt Kotlin 分析器 JAR
  pmd         PMD Java 分析器（~40 MB）
  repomap     tree-sitter 语法导航层（tree-sitter + language-pack 到独立 venv）
  all         上述全部
""",
    )
    ap.add_argument("--install", metavar="TOOL",
                    help="要安装的工具名（见上方列表）")
    ap.add_argument("--status", action="store_true",
                    help="显示各工具的安装状态")
    args = ap.parse_args()

    if args.status or not args.install:
        _print_status()
        return 0

    tool = args.install.lower()
    installers = {
        "venv": lambda: (str(ensure_venv()), False),
        "semgrep": ensure_semgrep,
        "detekt": ensure_detekt,
        "pmd": ensure_pmd,
        "repomap": lambda: (str(ensure_repomap_venv()), False),
    }
    if tool == "all":
        for name in ["venv", "semgrep", "detekt", "pmd", "repomap"]:
            _run_install(name, installers[name])
    elif tool in installers:
        _run_install(tool, installers[tool])
    else:
        print(f"未知工具: {tool}（可选: {', '.join(installers)}）", file=sys.stderr)
        return 1
    return 0


def _run_install(name: str, fn) -> None:
    try:
        path, fresh = fn()
        status = "已安装" if fresh else "已就绪"
        print(f"  {name}: {status} → {path}", file=sys.stderr)
    except Exception as e:
        print(f"  {name}: 失败 — {e}", file=sys.stderr)


def _print_status() -> None:
    print("scan-android 引擎状态:", file=sys.stderr)
    items = [
        ("venv", str(VENV_DIR), Path(_venv_python()).exists()),
        ("semgrep (venv)", venv_bin("semgrep"), Path(venv_bin("semgrep")).exists()),
        ("semgrep (PATH)", shutil.which("semgrep") or "", bool(shutil.which("semgrep"))),
        ("detekt", str(TOOLS_DIR / "detekt" / f"detekt-cli-{_DETEKT_VERSION}-all.jar"),
         (TOOLS_DIR / "detekt" / f"detekt-cli-{_DETEKT_VERSION}-all.jar").exists()),
        ("pmd", find_pmd() or str(TOOLS_DIR / "pmd"), bool(find_pmd())),
        ("repomap (tree-sitter venv)", str(REPOMAP_VENV_DIR),
         (REPOMAP_VENV_DIR / ("Scripts/python.exe" if platform.system() == "Windows" else "bin/python")).exists()),
        ("java", shutil.which("java") or "", bool(shutil.which("java"))),
    ]
    for name, path, ok in items:
        icon = "✅" if ok else "❌"
        print(f"  {icon} {name:<20} {path}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(_cli_main())
