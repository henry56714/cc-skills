"""
scan-android v2 引擎自动检测与安装。

每个 ensure_*() 函数:
  1. 检查工具是否已安装（venv / PATH / 本地缓存）
  2. 未安装则自动下载/安装
  3. 返回 (tool_path: str, was_just_installed: bool)

目录布局:
  ~/.scan-android/
    venv/           Python 虚拟环境（semgrep 等 pip 包，隔离于系统/conda）
    tools/          JVM 工具二进制（Detekt / Joern / CodeQL / FlowDroid）
    tools/joern/.download-failed   Joern 下载失败标记（1 小时内不重试）

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
import tarfile
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

# skill 根目录（requirements.txt 所在位置）
_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent

# 固定版本（定期更新以获取安全补丁）
_DETEKT_VERSION = "1.23.7"
_JOERN_VERSION_FALLBACK = "4.0.404"
_FLOWDROID_VERSION = "2.14.1"
_PMD_VERSION = "7.10.0"


# ---------------------------------------------------------------------------
# Python 虚拟环境管理
# ---------------------------------------------------------------------------


def ensure_venv() -> Path:
    """确保 scan-android 专属 venv 存在并返回其根路径。

    使用 Python 标准库 venv 模块创建，与系统 Python / conda / pyenv 完全隔离。
    venv 只用于 pip 包（目前仅 semgrep）；JVM 工具走 tools/ 目录。
    """
    python_bin = _venv_python()
    if Path(python_bin).exists():
        return VENV_DIR
    _print(f"[installer] 创建虚拟环境: {VENV_DIR}")
    import venv as _venv
    VENV_DIR.parent.mkdir(parents=True, exist_ok=True)
    # clear=False：若目录已存在但不完整，重建
    _venv.create(str(VENV_DIR), with_pip=True, clear=True)
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


# ---------------------------------------------------------------------------
# pip 包
# ---------------------------------------------------------------------------


def ensure_semgrep() -> tuple[str, bool]:
    """确保 semgrep 在 venv 中可用，返回 (executable_path, was_just_installed)。

    查找顺序:
      1. ~/.scan-android/venv/bin/semgrep  （管理的 venv，优先）
      2. shutil.which("semgrep")           （系统/conda 已有安装，兼容使用）
    首次安装时通过 pip 写入 venv，不污染系统环境。
    """
    # 1. venv 内已安装
    venv_semgrep = venv_bin("semgrep")
    if Path(venv_semgrep).exists():
        return venv_semgrep, False
    # 2. 系统 PATH 已有（使用但不移动；后续会在 venv 内补装）
    system_semgrep = shutil.which("semgrep")
    if system_semgrep:
        # 在 venv 内也安装一份以备 venv 优先路径生效
        _install_semgrep_to_venv()
        return venv_bin("semgrep") if Path(venv_bin("semgrep")).exists() else system_semgrep, False
    # 3. 都没有：创建 venv 并安装
    _install_semgrep_to_venv()
    path = venv_bin("semgrep")
    return path, True


def _install_semgrep_to_venv() -> None:
    ensure_venv()
    _print("[installer] 在虚拟环境中安装 semgrep（pip）...")
    subprocess.check_call(
        [_venv_python(), "-m", "pip", "install", "semgrep",
         "--quiet", "--disable-pip-version-check"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


# ---------------------------------------------------------------------------
# JVM 工具（JAR / 二进制）
# ---------------------------------------------------------------------------


def ensure_detekt() -> tuple[str, bool]:
    jar = TOOLS_DIR / "detekt" / f"detekt-cli-{_DETEKT_VERSION}-all.jar"
    if jar.exists():
        return str(jar), False
    _print(f"[installer] 下载 Detekt {_DETEKT_VERSION} (~64 MB)...")
    url = (
        f"https://github.com/detekt/detekt/releases/download/v{_DETEKT_VERSION}/"
        f"detekt-cli-{_DETEKT_VERSION}-all.jar"
    )
    jar.parent.mkdir(parents=True, exist_ok=True)
    _download(url, jar)
    return str(jar), True


def ensure_joern() -> tuple[str, bool]:
    # 先查 PATH
    existing = shutil.which("joern")
    if existing:
        return existing, False
    # 再查本地缓存
    local_bin = TOOLS_DIR / "joern" / "joern-cli" / "joern"
    if local_bin.exists():
        if not os.access(local_bin, os.X_OK):
            local_bin.chmod(local_bin.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return str(local_bin), False
    # 检查失败标记（避免因网络问题每次都重试 ~2 GB 下载）
    fail_marker = TOOLS_DIR / "joern" / ".download-failed"
    if fail_marker.exists():
        age = time.time() - fail_marker.stat().st_mtime
        if age < 3600:  # 1 小时内不重试
            raise RuntimeError(f"Joern 上次下载失败，将在 {int((3600 - age) / 60)} 分钟后重试")
    # 自动下载（v4+ 资产名为 joern-cli.zip，约 2 GB）
    version = _fetch_latest_github_version("joernio", "joern") or _JOERN_VERSION_FALLBACK
    _print(f"[installer] 下载 Joern {version} (~2 GB，请耐心等待)...")
    url = f"https://github.com/joernio/joern/releases/download/v{version}/joern-cli.zip"
    dest_zip = TOOLS_DIR / "joern" / f"joern-cli-{version}.zip"
    dest_zip.parent.mkdir(parents=True, exist_ok=True)
    try:
        _download(url, dest_zip)
    except Exception as e:
        fail_marker.parent.mkdir(parents=True, exist_ok=True)
        fail_marker.write_text(str(e))
        raise
    fail_marker.unlink(missing_ok=True)
    _print("[installer] 解压 Joern...")
    with zipfile.ZipFile(dest_zip) as zf:
        zf.extractall(TOOLS_DIR / "joern")
    cli_dir = TOOLS_DIR / "joern" / "joern-cli"
    if cli_dir.exists():
        for f in cli_dir.rglob("*"):
            if f.is_file() and f.suffix not in {".bat", ".jar", ".conf", ".properties", ".xml"}:
                f.chmod(f.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    dest_zip.unlink(missing_ok=True)
    return str(local_bin), True


def find_pmd() -> str | None:
    """返回可用的 pmd 可执行路径（PATH 或本地缓存），找不到返回 None。"""
    existing = shutil.which("pmd")
    if existing:
        return existing
    pmd_root = TOOLS_DIR / "pmd"
    cached = sorted(pmd_root.glob("pmd-bin-*/bin/pmd")) if pmd_root.exists() else []
    return str(cached[-1]) if cached else None


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
        zf.extractall(pmd_root)
    dest_zip.unlink(missing_ok=True)
    binp = pmd_root / f"pmd-bin-{version}" / "bin" / "pmd"
    if not binp.exists():
        raise RuntimeError("PMD 解压后未找到 bin/pmd")
    binp.chmod(binp.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(binp), True


def ensure_codeql() -> tuple[str, bool]:
    existing = shutil.which("codeql")
    if existing:
        return existing, False
    local_bin = TOOLS_DIR / "codeql" / "codeql"
    if local_bin.exists():
        return str(local_bin), False
    system = platform.system().lower()
    if system == "darwin":
        bundle = "codeql-bundle-osx64.tar.gz"
    elif system == "linux":
        bundle = "codeql-bundle-linux64.tar.gz"
    else:
        bundle = "codeql-bundle-win64.tar.gz"
    tar_path = TOOLS_DIR / "_dl" / bundle
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    # 仅在 tar 包不存在时才下载（跳过已完整下载的包，避免重复下载）
    if not tar_path.exists():
        _print(f"[installer] 下载 CodeQL bundle ({bundle}, ~773 MB，请耐心等待)...")
        url = f"https://github.com/github/codeql-action/releases/latest/download/{bundle}"
        _download(url, tar_path)
    else:
        _print(f"[installer] 使用已缓存的 CodeQL bundle: {tar_path}")
    _print("[installer] 解压 CodeQL...")
    extract_dir = TOOLS_DIR / "_codeql_extracted"
    # 清理上次不完整解压遗留的目录，避免权限受限文件导致 Permission denied
    if extract_dir.exists():
        _print("[installer] 清理旧解压目录...")
        _chmod_recursive(extract_dir)
        shutil.rmtree(extract_dir)
    with tarfile.open(tar_path) as tf:
        tf.extractall(extract_dir)
    for candidate in extract_dir.rglob("codeql"):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            codeql_dir = candidate.parent
            if (TOOLS_DIR / "codeql").exists():
                _chmod_recursive(TOOLS_DIR / "codeql")
                shutil.rmtree(TOOLS_DIR / "codeql")
            shutil.move(str(codeql_dir), str(TOOLS_DIR / "codeql"))
            break
    tar_path.unlink(missing_ok=True)
    _chmod_recursive(extract_dir)
    shutil.rmtree(extract_dir, ignore_errors=True)
    return str(local_bin), True


def _chmod_recursive(path: Path) -> None:
    """递归赋予目录及其内容用户读写执行权限，用于删除前解除权限锁定。"""
    try:
        for p in path.rglob("*"):
            try:
                p.chmod(p.stat().st_mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            except OSError:
                pass
        path.chmod(path.stat().st_mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except OSError:
        pass


def ensure_flowdroid() -> tuple[str, bool]:
    jar = TOOLS_DIR / "flowdroid" / f"flowdroid-{_FLOWDROID_VERSION}.jar"
    if jar.exists():
        return str(jar), False
    _print(f"[installer] 下载 FlowDroid {_FLOWDROID_VERSION}...")
    group_path = "de/fraunhofer/sit/sse/flowdroid/soot-infoflow-cmd"
    artifact = "soot-infoflow-cmd"
    url = (
        f"https://repo1.maven.org/maven2/{group_path}/{_FLOWDROID_VERSION}/"
        f"{artifact}-{_FLOWDROID_VERSION}-jar-with-dependencies.jar"
    )
    jar.parent.mkdir(parents=True, exist_ok=True)
    _download(url, jar)
    return str(jar), True


def ensure_adb() -> tuple[str, bool]:
    """检查 ADB 可用性。从不自动安装（属于 Android SDK，需用户管理）。"""
    existing = shutil.which("adb")
    if existing:
        return existing, False
    candidates = [
        Path.home() / "Library" / "Android" / "sdk" / "platform-tools" / "adb",
        Path("/usr/local/bin/adb"),
        Path(os.environ.get("ANDROID_HOME", "")) / "platform-tools" / "adb",
        Path(os.environ.get("ANDROID_SDK_ROOT", "")) / "platform-tools" / "adb",
    ]
    for c in candidates:
        if c.exists():
            return str(c), False
    return "", False


def check_java() -> tuple[bool, str]:
    """检查 Java 是否可用（Detekt / Joern / FlowDroid 需要 Java 11+）。"""
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
  joern       Joern CPG 分析器（~2 GB）
  codeql      CodeQL bundle（~2 GB，opt-in）
  flowdroid   FlowDroid JAR（opt-in）
  all         上述全部（codeql/flowdroid 除外）
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
        "joern": ensure_joern,
        "codeql": ensure_codeql,
        "flowdroid": ensure_flowdroid,
    }
    if tool == "all":
        for name in ["venv", "semgrep", "detekt", "pmd", "joern"]:
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
        ("joern", str(TOOLS_DIR / "joern" / "joern-cli" / "joern"),
         (TOOLS_DIR / "joern" / "joern-cli" / "joern").exists()),
        ("java", shutil.which("java") or "", bool(shutil.which("java"))),
        ("adb", shutil.which("adb") or "", bool(shutil.which("adb"))),
    ]
    for name, path, ok in items:
        icon = "✅" if ok else "❌"
        print(f"  {icon} {name:<20} {path}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(_cli_main())
