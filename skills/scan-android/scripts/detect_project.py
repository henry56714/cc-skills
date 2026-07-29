#!/usr/bin/env python3
"""
自动探测一个 Android 源码仓库的结构，输出 scan-android 工作流所需的元信息。
让 skill 不再硬编码任何特定项目的模块名 / flavor / lint 任务。

用法:
    detect_project.py [--repo-root DIR] [--config PATH]

行为：
1. 解析 settings.gradle / settings.gradle.kts 的 include(...) 得到 Gradle 模块列表；
   若无 settings 文件或解析为空，回退到「扫描含 build.gradle(.kts) 的目录」。
2. 探测各模块 build.gradle 是否声明 productFlavors，尽力提取 flavor 名。
3. 据此推荐一组优先级排序的 L0 lint 任务（工作流逐个尝试，用第一个成功的）。
4. 合并可选的项目级配置 .scan/config.json（覆盖/补充自动探测结果）。

输出 JSON 到 stdout：
    {
      "repo_root": "/abs/path",
      "is_git": true,
      "modules": ["app", "sdk"],            # 相对仓库根的模块目录
      "has_flavors": false,
      "flavors": [],
      "suggested_lint_tasks": ["lintDebug", "lint"],
      "default_excludes": [...],            # 通用排除
      "extra_excludes": [...],              # 来自 config 的项目级额外排除
      "source_extensions": [".java", ".kt", ".kts", ".xml", ...],
      "project_context": "",               # 注入 verifier 的项目背景（来自 config，可空）
      "language": "zh",                    # 生成文本字段的语言："zh" 或 "en"
      "config_path": ".scan/config.json",  # 若存在
      "notes": [...]
    }
"""

from __future__ import annotations

import argparse
import json
import locale
import os
import re
import sys
from pathlib import Path


# 与 CONVENTIONS.md «作用域语义» 保持一致的通用默认排除。
DEFAULT_EXCLUDES = [
    "**/build/**",
    "**/generated/**",
    "**/.cxx/**",
    "**/.externalNativeBuild/**",
    "**/CMakeFiles/**",
    "**/test/**",
    "**/androidTest/**",
    "**/.gradle/**",
    "**/.idea/**",
    "**/.vscode/**",
    "**/.scan/**",
    "**/.claude/**",
    "**/.codex/**",
    "local.properties",
    "**/local.properties",
    "docs/**",
    "**/docs/**",
]

DOCUMENTATION_EXCLUDES = {"docs/**", "**/docs/**"}

# 不只收 Java/Kotlin：Android 漏洞经常横跨构建脚本、资源配置、Web 资源和 JNI。
# 各引擎仍可自行挑选支持的语言；作用域层不能先把这些文件丢掉。
SOURCE_EXTENSIONS = [
    ".java", ".kt", ".kts", ".xml", ".aidl",
    ".gradle", ".properties", ".toml", ".pro", ".cfg",
    ".json", ".js", ".ts", ".dart",
    ".c", ".cc", ".cpp", ".h", ".hpp",
]

# settings.gradle(.kts) 里的 include 声明，覆盖 Groovy / Kotlin DSL 两种写法：
#   include ':app'
#   include ':app', ':sdk'
#   include(":app")
#   include(":feature:login")
_INCLUDE_RE = re.compile(r"""include\s*\(?\s*((?:['"][^'"]+['"]\s*,?\s*)+)\)?""")
_QUOTED_RE = re.compile(r"""['"]([^'"]+)['"]""")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--config", default=".scan/config.json")
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()
    out = detect_project(repo, args.config)
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def detect_project(repo: Path, config_path: str = ".scan/config.json") -> dict:
    """返回工程探测结果，供 CLI、scope 和 engine 编排共同复用。"""
    repo = repo.resolve()
    notes: list[str] = []
    modules = _detect_modules(repo, notes)
    flavors = _detect_flavors(repo, modules)
    suggested = _suggest_lint_tasks(flavors)

    config_file = repo / config_path
    config, config_error = _load_config_checked(config_file)
    if config_error:
        notes.append(f"invalid project config {config_path}: {config_error}; using safe defaults")
    elif config_file.exists():
        notes.append(f"loaded project config: {config_path}")
    configured_modules = _string_list(config.get("modules"))
    configured_lint_tasks = _string_list(config.get("lint_tasks"))
    if configured_modules:
        modules = configured_modules
    elif config.get("modules") not in (None, []):
        notes.append("ignored invalid config.modules (expected array of strings)")
    if configured_lint_tasks:
        suggested = configured_lint_tasks
    elif config.get("lint_tasks") not in (None, []):
        notes.append("ignored invalid config.lint_tasks (expected array of strings)")

    default_excludes = list(DEFAULT_EXCLUDES)
    if config.get("include_documentation") is True:
        default_excludes = [p for p in default_excludes if p not in DOCUMENTATION_EXCLUDES]
        notes.append("documentation source explicitly included by config")

    return {
        "repo_root": str(repo),
        # 支持普通 clone、git worktree（.git 是文件）以及从子目录指定的仓库根。
        "is_git": _is_git_repo(repo),
        "modules": modules,
        "has_flavors": bool(flavors),
        "flavors": flavors,
        "suggested_lint_tasks": suggested,
        "default_excludes": default_excludes,
        "extra_excludes": _string_list(config.get("extra_excludes")),
        "source_extensions": SOURCE_EXTENSIONS,
        "project_context": str(config.get("project_context", "")),
        "language": _detect_language(config),
        "config_path": config_path if config_file.exists() else None,
        "config": config,
        "notes": notes,
    }


def _is_git_repo(repo: Path) -> bool:
    try:
        import subprocess
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5,
        )
        return proc.returncode == 0 and proc.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def _detect_modules(repo: Path, notes: list[str]) -> list[str]:
    """优先解析 settings.gradle(.kts)；失败则回退到目录扫描。"""
    for name in ("settings.gradle", "settings.gradle.kts"):
        sf = repo / name
        if not sf.exists():
            continue
        text = sf.read_text(encoding="utf-8", errors="replace")
        # 去掉行注释，避免命中被注释掉的 include
        text = re.sub(r"//[^\n]*", "", text)
        paths: list[str] = []
        for m in _INCLUDE_RE.finditer(text):
            for q in _QUOTED_RE.findall(m.group(1)):
                rel = q.lstrip(":").replace(":", "/")
                if rel and (repo / rel).is_dir():
                    paths.append(rel)
        # 去重保序
        seen: set[str] = set()
        modules = [p for p in paths if not (p in seen or seen.add(p))]
        if modules:
            notes.append(f"modules from {name} ({len(modules)})")
            return modules
        notes.append(f"{name} present but no resolvable include() found")

    # 回退：扫描含 build.gradle(.kts) 的目录（深度 <= 2，排除根与 buildSrc）
    modules = []
    for gradle in list(repo.glob("*/build.gradle")) + list(repo.glob("*/build.gradle.kts")) \
            + list(repo.glob("*/*/build.gradle")) + list(repo.glob("*/*/build.gradle.kts")):
        rel = gradle.parent.relative_to(repo).as_posix()
        if rel in ("buildSrc",) or rel.startswith("build/"):
            continue
        if rel not in modules:
            modules.append(rel)
    notes.append(f"modules by build.gradle scan ({len(modules)})")
    return sorted(modules)


def _detect_flavors(repo: Path, modules: list[str]) -> list[str]:
    """尽力从各模块 build.gradle(.kts) 的 productFlavors 块提取 flavor 名。"""
    flavors: list[str] = []
    for mod in modules:
        for name in ("build.gradle", "build.gradle.kts"):
            bf = repo / mod / name
            if not bf.exists():
                continue
            block = _extract_block(bf.read_text(encoding="utf-8", errors="replace"), "productFlavors")
            if not block:
                continue
            # Groovy: `paid { ... }`  /  Kotlin DSL: `create("paid") { ... }`
            for fm in re.finditer(r"create\s*\(\s*['\"]([A-Za-z][\w]*)['\"]", block):
                flavors.append(fm.group(1))
            for fm in re.finditer(r"^\s*([A-Za-z][\w]*)\s*\{", block, re.MULTILINE):
                name_ = fm.group(1)
                if name_ not in ("setDimension", "dimension", "create"):
                    flavors.append(name_)
    # 去重保序
    seen: set[str] = set()
    return [f for f in flavors if not (f in seen or seen.add(f))]


def _extract_block(text: str, keyword: str) -> str | None:
    """提取 `keyword { ... }` 的大括号内文本（简单括号配平）。"""
    idx = text.find(keyword)
    while idx != -1:
        brace = text.find("{", idx)
        if brace == -1:
            return None
        depth = 0
        for i in range(brace, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[brace + 1:i]
        idx = text.find(keyword, idx + len(keyword))
    return None


def _suggest_lint_tasks(flavors: list[str]) -> list[str]:
    """推荐优先级排序的 lint 任务；工作流逐个尝试，取第一个成功的。"""
    tasks: list[str] = []
    for f in flavors:
        tasks.append(f"lint{f[:1].upper()}{f[1:]}Debug")
    tasks.append("lintDebug")
    tasks.append("lint")
    # 去重保序
    seen: set[str] = set()
    return [t for t in tasks if not (t in seen or seen.add(t))]


def _detect_language(config: dict) -> str:
    """输出语言检测，优先级：config > POSIX env vars > Python locale > 默认 zh。

    检测顺序：
    1. config.language（显式覆盖，最高优先级）
    2. LC_ALL > LC_MESSAGES > LANG（macOS / Linux / Windows Git Bash）
       LC_NUMERIC / LC_TIME 仅影响数字/日期格式，忽略。
    3. locale.getdefaultlocale()（Windows 原生 PowerShell / CMD 兜底）
    4. 默认 "zh"
    """
    cfg_lang = config.get("language", "")
    if isinstance(cfg_lang, str) and cfg_lang:
        return "zh" if cfg_lang.lower().startswith("zh") else "en"

    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(var, "")
        if val:
            return "zh" if val.lower().startswith("zh") else "en"

    # Windows 原生环境不设置 POSIX locale 变量，通过 Python locale 模块读取系统语言。
    # 用 setlocale("") 激活系统 locale 后再读取，避免使用已废弃的 getdefaultlocale()。
    try:
        saved = locale.setlocale(locale.LC_ALL)
        locale.setlocale(locale.LC_ALL, "")
        code = locale.getlocale()[0] or ""
        locale.setlocale(locale.LC_ALL, saved)
        if code:
            return "zh" if code.lower().startswith("zh") else "en"
    except Exception:
        pass

    return "zh"


def _load_config(path: Path) -> dict:
    return _load_config_checked(path)[0]


def _load_config_checked(path: Path) -> tuple[dict, str]:
    if not path.exists():
        return {}, ""
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}, "top-level JSON must be an object"
        return data, ""
    except (OSError, json.JSONDecodeError) as exc:
        return {}, str(exc)


def _string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


if __name__ == "__main__":
    sys.exit(main())
