#!/usr/bin/env python3
"""
自动探测一个 Android 源码仓库的结构，输出 scan-android 工作流所需的元信息。
让 skill 不再硬编码任何特定项目的模块名 / flavor / lint 任务。

用法:
    detect_project.py [--repo-root DIR] [--config PATH]

行为：
1. 解析 settings.gradle / settings.gradle.kts 的 include(...) 得到 Gradle 模块列表；
   若无 settings 文件或解析为空，回退到「扫描含 build.gradle(.kts) 的目录」。
2. 探测各模块 source set 与 build.gradle 中的 productFlavors。
3. 据此推荐发布/shipping Lint 任务（工作流逐项执行和记账）。
4. 默认仅把 .scan/config.json 当不可信仓库数据；调用方显式信任后才合并策略字段。

输出 JSON 到 stdout：
    {
      "repo_root": "/abs/path",
      "is_git": true,
      "modules": ["app", "sdk"],            # 相对仓库根的模块目录
      "has_flavors": false,
      "flavors": [],
      "source_sets": {"app": ["main", "debug", "release"]},
      "suggested_lint_tasks": ["lintRelease", "lint"],
      "default_excludes": [...],            # 通用排除
      "extra_excludes": [...],              # 来自 config 的项目级额外排除
      "source_extensions": [".java", ".kt", ".kts", ".xml", ...],
      "project_context": "",               # 永远不接受仓库配置作为 prompt 指令
      "repository_context_hint": "",       # 未信任的数据提示，仅供审查者参考
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

from lib_scan import resolve_cli_path, resolve_repo_path


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
    ".json", ".js", ".ts", ".dart", ".html", ".htm", ".sql",
    ".proto", ".mk", ".yaml", ".yml",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".rs",
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
    ap.add_argument(
        "--trust-project-config", action="store_true",
        help="允许目标仓库配置改变作用域/任务；仅用于已审阅的可信配置",
    )
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()
    out = detect_project(repo, args.config, trust_project_config=args.trust_project_config)
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def detect_project(
    repo: Path,
    config_path: str = ".scan/config.json",
    *,
    trust_project_config: bool = False,
) -> dict:
    """返回工程探测结果，供 CLI、scope 和 engine 编排共同复用。"""
    repo = repo.resolve()
    notes: list[str] = []
    modules = _detect_modules(repo, notes)
    flavors = _detect_flavors(repo, modules)
    android_config = _detect_android_config(repo, modules)
    build_types = sorted({
        value for module in android_config.values()
        for value in module.get("build_types", [])
    })
    suggested = _suggest_lint_tasks(flavors, build_types)

    try:
        config_file = resolve_cli_path(repo, config_path, label="project config")
        declared_config, config_error = _load_config_checked(config_file)
    except ValueError as exc:
        config_file = repo / config_path
        declared_config, config_error = {}, str(exc)
    config = declared_config if trust_project_config else {}
    if config_error:
        notes.append(f"invalid project config {config_path}: {config_error}; using safe defaults")
    elif config_file.exists() and trust_project_config:
        notes.append(f"loaded trusted project config: {config_path}")
    elif config_file.exists():
        notes.append(
            f"ignored untrusted project scan policy: {config_path}; pass --trust-project-config only after review"
        )
    configured_modules, unsafe_configured_modules = _safe_modules(
        repo, _string_list(config.get("modules"))
    )
    if unsafe_configured_modules:
        notes.append(
            "ignored unsafe config.modules entries: "
            + ", ".join(unsafe_configured_modules)
        )
    configured_lint_tasks = _string_list(config.get("lint_tasks"))
    if configured_modules:
        modules = configured_modules
        flavors = _detect_flavors(repo, modules)
        android_config = _detect_android_config(repo, modules)
        build_types = sorted({
            value for module in android_config.values()
            for value in module.get("build_types", [])
        })
        suggested = _suggest_lint_tasks(flavors, build_types)
    elif config.get("modules") not in (None, []) and not unsafe_configured_modules:
        notes.append("ignored invalid config.modules (expected array of strings)")
    if configured_lint_tasks:
        valid_tasks = [task for task in configured_lint_tasks if _valid_gradle_task(task)]
        invalid_tasks = [task for task in configured_lint_tasks if task not in valid_tasks]
        if invalid_tasks:
            notes.append("ignored unsafe config.lint_tasks entries: " + ", ".join(invalid_tasks))
        if valid_tasks:
            suggested = valid_tasks
    elif config.get("lint_tasks") not in (None, []):
        notes.append("ignored invalid config.lint_tasks (expected array of strings)")
    source_sets = _detect_source_sets(repo, modules)

    default_excludes = list(DEFAULT_EXCLUDES)
    if config.get("include_documentation") is True:
        default_excludes = [p for p in default_excludes if p not in DOCUMENTATION_EXCLUDES]
        notes.append("documentation source explicitly included by config")

    raw_context = declared_config.get("project_context", "")
    repository_context_hint = raw_context if isinstance(raw_context, str) else ""
    if repository_context_hint:
        notes.append(
            "config.project_context is untrusted repository data; it is not injected as agent instructions"
        )

    return {
        "repo_root": str(repo),
        # 支持普通 clone、git worktree（.git 是文件）以及从子目录指定的仓库根。
        "is_git": _is_git_repo(repo),
        "modules": modules,
        "has_flavors": bool(flavors),
        "flavors": flavors,
        "source_sets": source_sets,
        "android_config": android_config,
        "build_types": build_types,
        "shipping_variants": _shipping_variants(flavors, build_types),
        "suggested_lint_tasks": suggested,
        "default_excludes": default_excludes,
        "extra_excludes": _string_list(config.get("extra_excludes")),
        "source_extensions": SOURCE_EXTENSIONS,
        "project_context": "",
        "repository_context_hint": repository_context_hint,
        "repository_context_untrusted": bool(repository_context_hint),
        "language": _detect_language(config),
        "config_path": config_path if config_file.exists() else None,
        "config": config,
        "config_trusted": trust_project_config,
        "declared_config_keys": sorted(str(key) for key in declared_config),
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
        try:
            safe_sf = resolve_repo_path(repo, sf, label=name)
        except ValueError:
            notes.append(f"ignored {name} symlink/path outside repository")
            continue
        if not safe_sf.is_file():
            continue
        text = safe_sf.read_text(encoding="utf-8", errors="replace")
        # 去掉行注释，避免命中被注释掉的 include
        text = re.sub(r"//[^\n]*", "", text)
        paths: list[str] = []
        for m in _INCLUDE_RE.finditer(text):
            for q in _QUOTED_RE.findall(m.group(1)):
                rel = q.lstrip(":").replace(":", "/")
                if rel:
                    safe, _unsafe = _safe_modules(repo, [rel])
                    paths.extend(safe)
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
        try:
            safe_gradle = resolve_repo_path(repo, gradle, label="module build file")
            rel = safe_gradle.parent.relative_to(repo.resolve()).as_posix()
        except ValueError:
            continue
        if rel in ("buildSrc",) or rel.startswith("build/"):
            continue
        if rel not in modules:
            modules.append(rel)
    notes.append(f"modules by build.gradle scan ({len(modules)})")
    return sorted(modules)


def _safe_modules(repo: Path, values: list[str]) -> tuple[list[str], list[str]]:
    """Normalize module directories without following paths outside the repo."""
    safe: list[str] = []
    unsafe: list[str] = []
    for raw in values:
        candidate = Path(raw.strip().replace("\\", "/"))
        if not raw.strip() or candidate.is_absolute():
            unsafe.append(raw)
            continue
        try:
            resolved = resolve_repo_path(repo, candidate, label="module")
            normalized = resolved.relative_to(repo.resolve()).as_posix()
        except ValueError:
            unsafe.append(raw)
            continue
        if normalized == "." or not resolved.is_dir():
            unsafe.append(raw)
            continue
        if normalized not in safe:
            safe.append(normalized)
    return safe, unsafe


def _detect_flavors(repo: Path, modules: list[str]) -> list[str]:
    """尽力从各模块 build.gradle(.kts) 的 productFlavors 块提取 flavor 名。"""
    flavors: list[str] = []
    for mod in modules:
        for name in ("build.gradle", "build.gradle.kts"):
            bf = repo / mod / name
            try:
                safe_bf = resolve_repo_path(repo, bf, label="module build file")
            except ValueError:
                continue
            if not safe_bf.is_file():
                continue
            block = _extract_block(
                safe_bf.read_text(encoding="utf-8", errors="replace"), "productFlavors"
            )
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


def _detect_source_sets(repo: Path, modules: list[str]) -> dict[str, list[str]]:
    """List physical Android source-set directories for every detected module."""
    result: dict[str, list[str]] = {}
    candidates = modules or [""]
    for module in candidates:
        src = repo / module / "src"
        try:
            safe_src = resolve_repo_path(repo, src, label="module source set")
        except ValueError:
            continue
        if not safe_src.is_dir():
            continue
        names = sorted(path.name for path in safe_src.iterdir() if path.is_dir())
        if names:
            result[module or "."] = names
    return result


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


def _shipping_build_types(build_types: list[str] | None) -> list[str]:
    values = list(build_types or [])
    shipping = [
        value for value in values
        if value.lower() not in {"debug", "test", "androidtest"}
        and not value.lower().endswith("debug")
    ]
    return shipping or ["release"]


def _shipping_variants(flavors: list[str], build_types: list[str] | None) -> list[str]:
    types = _shipping_build_types(build_types)
    if not flavors:
        return types
    return [f"{flavor}{kind[:1].upper()}{kind[1:]}" for flavor in flavors for kind in types]


def _suggest_lint_tasks(flavors: list[str], build_types: list[str] | None = None) -> list[str]:
    """Recommend release/shipping Lint tasks; every returned task is accounted for."""
    tasks: list[str] = []
    for variant in _shipping_variants(flavors, build_types):
        tasks.append(f"lint{variant[:1].upper()}{variant[1:]}")
    if flavors:
        for kind in _shipping_build_types(build_types):
            tasks.append(f"lint{kind[:1].upper()}{kind[1:]}")
    tasks.append("lint")
    # 去重保序
    seen: set[str] = set()
    return [t for t in tasks if not (t in seen or seen.add(t))]


def _valid_gradle_task(task: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9:_-]*", task))


def _detect_android_config(repo: Path, modules: list[str]) -> dict[str, dict]:
    """Best-effort release-relevant Gradle facts; never execute Gradle."""
    result: dict[str, dict] = {}
    for module in modules or [""]:
        build_file = None
        for name in ("build.gradle.kts", "build.gradle"):
            candidate = repo / module / name
            try:
                safe_candidate = resolve_repo_path(repo, candidate, label="module build file")
            except ValueError:
                continue
            if safe_candidate.is_file():
                build_file = safe_candidate
                break
        if build_file is None:
            continue
        text = build_file.read_text(encoding="utf-8", errors="replace")
        facts: dict[str, object] = {"build_file": build_file.relative_to(repo).as_posix()}
        for key, aliases in {
            "compile_sdk": ("compileSdk", "compileSdkVersion"),
            "min_sdk": ("minSdk", "minSdkVersion"),
            "target_sdk": ("targetSdk", "targetSdkVersion"),
        }.items():
            alternation = "|".join(aliases)
            match = re.search(rf"\b(?:{alternation})\b\s*(?:=|\(|\s)\s*['\"]?(\d+)", text)
            if match:
                facts[key] = int(match.group(1))
        for key, name in (("namespace", "namespace"), ("application_id", "applicationId")):
            match = re.search(rf"\b{name}\b\s*(?:=|\s)\s*['\"]([^'\"]+)['\"]", text)
            if match:
                facts[key] = match.group(1)

        build_types: list[str] = []
        block = _extract_block(text, "buildTypes")
        if block:
            build_types.extend(re.findall(r"create\s*\(\s*['\"]([A-Za-z][\w]*)['\"]", block))
            build_types.extend(
                name for name in re.findall(r"^\s*([A-Za-z][\w]*)\s*\{", block, re.MULTILINE)
                if name not in {"create", "getByName", "maybeCreate"}
            )
        if not build_types and re.search(r"com\.android\.(?:application|library)", text):
            build_types = ["debug", "release"]
        facts["build_types"] = list(dict.fromkeys(build_types))

        signing_block = _extract_block(text, "signingConfigs") or ""
        signing_names = re.findall(r"create\s*\(\s*['\"]([A-Za-z][\w]*)['\"]", signing_block)
        signing_names += re.findall(r"^\s*([A-Za-z][\w]*)\s*\{", signing_block, re.MULTILINE)
        facts["signing_config_names"] = sorted(set(signing_names) - {"create"})
        placeholder_keys = re.findall(
            r"manifestPlaceholders(?:\s*\[[\"']([^\"']+)[\"']\]|\s*[+=]\s*mapOf\s*\(\s*[\"']([^\"']+)[\"'])",
            text,
        )
        facts["manifest_placeholder_keys"] = sorted({a or b for a, b in placeholder_keys})
        result[module or "."] = facts
    return result


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
