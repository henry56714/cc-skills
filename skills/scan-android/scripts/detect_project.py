#!/usr/bin/env python3
"""
自动探测一个 Android 仓库的结构，输出 scan-android 工作流所需的元信息。
让 skill 不再硬编码任何特定项目的模块名 / flavor / lint 任务，从而能扫描任意 APK 工程。

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
      "source_extensions": [".java", ".kt", ".xml", ".aidl"],
      "project_context": "",               # 注入 verifier 的项目背景（来自 config，可空）
      "default_checks": ["security", "stability", "perf"],
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
    "**/test/**",
    "**/androidTest/**",
    "**/.gradle/**",
    "**/.idea/**",
]

SOURCE_EXTENSIONS = [".java", ".kt", ".xml", ".aidl"]
DEFAULT_CHECKS = ["security", "stability", "perf"]

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
    notes: list[str] = []

    modules = _detect_modules(repo, notes)
    flavors = _detect_flavors(repo, modules)
    suggested = _suggest_lint_tasks(flavors)

    config = _load_config(repo / args.config)
    if config:
        notes.append(f"loaded project config: {args.config}")

    # config 覆盖 / 补充
    if config.get("modules"):
        modules = list(config["modules"])
    extra_excludes = list(config.get("extra_excludes", []))
    project_context = config.get("project_context", "")
    if config.get("lint_tasks"):
        suggested = list(config["lint_tasks"])
    default_checks = list(config.get("default_checks", DEFAULT_CHECKS))
    language = _detect_language(config)

    out = {
        "repo_root": str(repo),
        "is_git": (repo / ".git").exists(),
        "modules": modules,
        "has_flavors": bool(flavors),
        "flavors": flavors,
        "suggested_lint_tasks": suggested,
        "default_excludes": DEFAULT_EXCLUDES,
        "extra_excludes": extra_excludes,
        "source_extensions": SOURCE_EXTENSIONS,
        "project_context": project_context,
        "default_checks": default_checks,
        "language": language,
        "config_path": args.config if config else None,
        "notes": notes,
    }
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


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
    if cfg_lang:
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
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


if __name__ == "__main__":
    sys.exit(main())
